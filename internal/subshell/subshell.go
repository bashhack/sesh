package subshell

import (
	"errors"
	"fmt"
	"github.com/bashhack/sesh/internal/aws"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

type Config struct {
	ServiceName string
	Variables   map[string]string
	Expiry      time.Time

	ShellCustomizer ShellCustomizer
}

type ShellCustomizer interface {
	GetZshInitScript() string

	GetBashInitScript() string

	GetFallbackInitScript() string

	GetPromptPrefix() string

	GetWelcomeMessage() string
}

func Launch(config Config, stdout, stderr *os.File) error {
	if os.Getenv("SESH_ACTIVE") == "1" {
		return fmt.Errorf("already in a sesh environment, nested sessions are not supported.\nPlease exit the current sesh shell first with 'exit' or Ctrl+D")
	}

	env := os.Environ()

	for key, value := range config.Variables {
		env = filterEnv(env, key)
		env = append(env, fmt.Sprintf("%s=%s", key, value))
	}

	env = append(env, fmt.Sprintf("SESH_ACTIVE=1"))
	env = append(env, fmt.Sprintf("SESH_SERVICE=%s", config.ServiceName))
	env = append(env, "SESH_DISABLE_INTEGRATION=1")

	env = append(env, fmt.Sprintf("SESH_START_TIME=%d", time.Now().Unix()))
	if !config.Expiry.IsZero() {
		env = append(env, fmt.Sprintf("SESH_EXPIRY=%d", config.Expiry.Unix()))
		env = append(env, fmt.Sprintf("SESH_TOTAL_DURATION=%d", config.Expiry.Unix()-time.Now().Unix()))
	}

	shell := os.Getenv("SHELL")
	if shell == "" {
		shell = "/bin/sh"
	}

	var cmd *exec.Cmd
	var err error

	switch {
	case shell == "/bin/zsh" || filepath.Base(shell) == "zsh":
		cmd, err = setupZshShell(shell, config, env)
		if err != nil {
			return fmt.Errorf("failed to set up zsh shell: %w", err)
		}
	case shell == "/bin/bash" || filepath.Base(shell) == "bash":
		cmd = setupBashShell(shell, config, env)
	default:
		cmd = setupFallbackShell(shell, config, env)
	}

	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = env

	fmt.Fprintf(stdout, "Starting secure shell with %s credentials\n", config.ServiceName)
	err := cmd.Run()

	fmt.Fprintf(stdout, "Exited secure shell\n")

	if err != nil {
		// ExitError is the standard error type when a shell exits, whether by
		// normal means (exit command, Ctrl+D) or signals. This is expected behavior
		// for subshell implementations and shouldn't be reported as an error.
		// In my testing, tools like Python's virtualenv have similar behavior -
		// swallowing events like Ctrl+C, for example.
		var exitError *exec.ExitError
		if errors.As(err, &exitError) {
			return nil
		}

		// Only return truly unexpected errors...
		return fmt.Errorf("subshell encountered an unexpected error: %w", err)
	}

	return nil
}

func setupZshShell(shell string, config Config, env []string) (*exec.Cmd, error) {
	// Create a temporary ZDOTDIR for zsh
	tmpDir, err := os.MkdirTemp("", "sesh_zsh")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp dir for zsh: %w", err)
	}
	zshrc := filepath.Join(tmpDir, ".zshrc")

	// Construct zsh init script with common functions
	if writeErr := os.WriteFile(zshrc, []byte(aws.ZshPrompt), 0644); writeErr != nil {
		return nil, fmt.Errorf("failed to write temp zshrc: %w", writeErr)
	}
	env = append(env, fmt.Sprintf("ZDOTDIR=%s", tmpDir))
	return exec.Command(shell), nil
}

func setupBashShell(shell string, config Config, env []string) *exec.Cmd {

}

func setupFallbackShell(shell string, config Config, env []string) *exec.Cmd {

}

func filterEnv(env []string, key string) []string {
	var result []string
	prefix := key + "="
	for _, item := range env {
		if len(item) < len(prefix) || item[:len(prefix)] != prefix {
			result = append(result, item)
		}
	}
	return result
}
