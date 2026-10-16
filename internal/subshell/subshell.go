// Package subshell starts the shell sesh aws opens: the user's own shell,
// with their startup files, plus the session's credentials, a prompt
// prefix, and sesh's helper commands.
package subshell

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/bashhack/sesh/internal/shell"
)

// Config holds the parameters needed to launch an authenticated subshell.
type Config struct {
	Expiry          time.Time
	ShellCustomizer ShellCustomizer
	Variables       map[string]string
	ServiceName     string
}

// ShellCustomizer is what a service adds to the shell.
type ShellCustomizer interface {
	// Functions is shell code that sh, bash and zsh all run: the helper
	// commands, and a line saying the shell is ready.
	Functions() string
	// PromptPrefix goes before the user's prompt, such as "(sesh:aws) ".
	PromptPrefix() string
}

// ShellConfig holds the information needed to launch a shell
type ShellConfig struct {
	Cleanup     func() // Removes temp files created during shell setup; safe to call even if nil
	Shell       string
	ServiceName string
	Args        []string
	Env         []string
}

// GetShellConfig builds the shell to start: $SHELL (or /bin/sh), its
// arguments, its environment, and the startup files written for it.
//
// The environment is this process's, with the service's variables and
// SESH_ACTIVE, SESH_SERVICE, SESH_EXPIRY and SESH_TOTAL_DURATION, and
// without SESH_MASTER_PASSWORD, which no program in the shell needs.
//
// The user's own startup files run first, then sesh's: zsh's .zshenv and
// .zshrc from where they live (ZDOTDIR, or the home folder), bash's
// ~/.bashrc, or the file sh's ENV names. History goes where the user's
// files say.
func GetShellConfig(config Config) (*ShellConfig, error) {
	if config.ShellCustomizer == nil {
		return nil, fmt.Errorf("shell customizer is required")
	}

	env := FilterEnv(os.Environ(), "SESH_MASTER_PASSWORD")
	for key, value := range config.Variables {
		env = FilterEnv(env, key)
		env = append(env, fmt.Sprintf("%s=%s", key, value))
	}
	env = append(env, "SESH_ACTIVE=1", fmt.Sprintf("SESH_SERVICE=%s", config.ServiceName))
	if !config.Expiry.IsZero() {
		now := time.Now().Unix()
		env = append(env,
			fmt.Sprintf("SESH_EXPIRY=%d", config.Expiry.Unix()),
			fmt.Sprintf("SESH_TOTAL_DURATION=%d", config.Expiry.Unix()-now),
		)
	}

	sh := os.Getenv("SHELL")
	if sh == "" {
		sh = "/bin/sh"
	}
	sc := &ShellConfig{Shell: sh, ServiceName: config.ServiceName}
	var err error
	switch filepath.Base(sh) {
	case "zsh":
		var dir string
		if env, dir, err = SetupZshShell(config, env); err != nil {
			return nil, fmt.Errorf("failed to set up zsh shell: %w", err)
		}
		sc.Cleanup = removing(dir)
	case "bash":
		var rc string
		if rc, err = SetupBashShell(config); err != nil {
			return nil, fmt.Errorf("failed to set up bash shell: %w", err)
		}
		sc.Args = []string{"--rcfile", rc}
		sc.Cleanup = removing(rc)
	default:
		var rc string
		if env, rc, err = SetupFallbackShell(config, env); err != nil {
			return nil, fmt.Errorf("failed to set up fallback shell: %w", err)
		}
		sc.Cleanup = removing(rc)
	}
	sc.Env = env
	return sc, nil
}

// removing is a cleanup that removes path, and says so if it can't.
func removing(path string) func() {
	return func() {
		if err := os.RemoveAll(path); err != nil {
			fmt.Fprintf(os.Stderr, "warning: failed to clean up %s: %v\n", path, err)
		}
	}
}

// envValue is name's value in env, or "".
func envValue(env []string, name string) string {
	for _, kv := range env {
		if v, ok := strings.CutPrefix(kv, name+"="); ok {
			return v
		}
	}
	return ""
}

// SetupZshShell writes a temporary ZDOTDIR whose .zshenv and .zshrc run
// the user's own (from their ZDOTDIR, or the home folder; their .zshenv
// may move it), then add sesh's prompt prefix and helpers. ZDOTDIR is the
// user's again before their .zshrc runs, so everything after (history,
// completion's cache, plugins) is where they keep it. It returns env with
// ZDOTDIR pointing there, and the folder, to remove after.
func SetupZshShell(config Config, env []string) ([]string, string, error) {
	userDir := envValue(env, "ZDOTDIR")
	if userDir == "" {
		userDir = envValue(env, "HOME")
	}
	dir, err := os.MkdirTemp("", "sesh_zsh")
	if err != nil {
		return nil, "", fmt.Errorf("failed to create temp dir for zsh: %w", err)
	}
	zshenv := fmt.Sprintf(`# sesh: the user's own .zshenv first, from where it lives.
__sesh_dir=%s
ZDOTDIR=%s
[[ -r $ZDOTDIR/.zshenv ]] && source $ZDOTDIR/.zshenv
__sesh_user_zdotdir=$ZDOTDIR
ZDOTDIR=$__sesh_dir
`, shell.Quote(dir), shell.Quote(userDir))
	prefix := config.ShellCustomizer.PromptPrefix()
	zshrc := fmt.Sprintf(`# sesh: the user's own .zshrc first, with ZDOTDIR theirs again.
ZDOTDIR=$__sesh_user_zdotdir
[[ $HISTFILE == $__sesh_dir/* ]] && HISTFILE=$ZDOTDIR/.zsh_history
unset __sesh_dir __sesh_user_zdotdir
[[ -r $ZDOTDIR/.zshrc ]] && source $ZDOTDIR/.zshrc

%s
# The prefix goes back on whenever a prompt theme redraws the prompt.
__sesh_prompt() { [[ $PROMPT == %s* ]] || PROMPT=%s$PROMPT }
precmd_functions+=(__sesh_prompt)
__sesh_prompt
`, config.ShellCustomizer.Functions(), shell.Quote(prefix), shell.Quote(prefix))
	for name, body := range map[string]string{".zshenv": zshenv, ".zshrc": zshrc} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			_ = os.RemoveAll(dir) //nolint:errcheck // the write's error is the one to report
			return nil, "", fmt.Errorf("failed to write the zsh startup files: %w", err)
		}
	}
	return append(FilterEnv(env, "ZDOTDIR"), "ZDOTDIR="+dir), dir, nil
}

// SetupBashShell writes a temporary rcfile for bash --rcfile, which bash
// reads in place of ~/.bashrc: it runs ~/.bashrc, then adds sesh's prompt
// prefix and helpers. It returns the file's path, to remove after.
func SetupBashShell(config Config) (string, error) {
	prefix := shell.Quote(config.ShellCustomizer.PromptPrefix())
	rc := fmt.Sprintf(`# sesh: the user's own ~/.bashrc first.
[ -r "$HOME/.bashrc" ] && . "$HOME/.bashrc"

%s
# The prefix goes back on whenever a prompt command redraws the prompt.
__sesh_prompt() { case "$PS1" in %s*) ;; *) PS1=%s"$PS1" ;; esac; }
PROMPT_COMMAND="${PROMPT_COMMAND:+$PROMPT_COMMAND
}__sesh_prompt"
__sesh_prompt
`, config.ShellCustomizer.Functions(), prefix, prefix)
	return writeTemp("sesh_bashrc", rc)
}

// SetupFallbackShell writes a temporary file for another shell to read at
// start through ENV, as sh and dash do: it runs the user's own ENV file,
// if they have one, then adds sesh's prompt prefix and helpers. A shell
// that doesn't read ENV (fish) gets the credentials alone. It returns env
// with ENV pointing at the file, and the file's path, to remove after.
func SetupFallbackShell(config Config, env []string) ([]string, string, error) {
	prefix := shell.Quote(config.ShellCustomizer.PromptPrefix())
	var own string
	if userEnv := envValue(env, "ENV"); userEnv != "" {
		own = fmt.Sprintf("[ -r %s ] && . %s\n", shell.Quote(userEnv), shell.Quote(userEnv))
	}
	rc := fmt.Sprintf(`# sesh: the user's own ENV file first.
%s
%s
case "$PS1" in %s*) ;; *) PS1=%s"${PS1:-$ }" ;; esac
`, own, config.ShellCustomizer.Functions(), prefix, prefix)
	name, err := writeTemp("sesh_shellrc", rc)
	if err != nil {
		return nil, "", err
	}
	return append(FilterEnv(env, "ENV"), "ENV="+name), name, nil
}

// writeTemp writes body to a new temporary file only the user can read,
// named from pattern, and returns its path.
func writeTemp(pattern, body string) (path string, err error) {
	f, err := os.CreateTemp("", pattern)
	if err != nil {
		return "", fmt.Errorf("failed to create a temporary startup file: %w", err)
	}
	defer func() {
		if cerr := f.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("failed to write the temporary startup file: %w", cerr)
		}
		if err != nil {
			_ = os.Remove(f.Name()) //nolint:errcheck // the write's error is the one to report
		}
	}()
	if _, err := f.WriteString(body); err != nil {
		return "", fmt.Errorf("failed to write the temporary startup file: %w", err)
	}
	return f.Name(), nil
}

// FilterEnv returns env without key's entries.
func FilterEnv(env []string, key string) []string {
	result := make([]string, 0, len(env))
	prefix := key + "="
	for _, item := range env {
		if !strings.HasPrefix(item, prefix) {
			result = append(result, item)
		}
	}
	return result
}
