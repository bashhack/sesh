package subshell

import (
	"fmt"
	"io"
	"os"
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

func Launch(config Config, stdout, stderr io.Writer) error {
	// TODO: Implement the logic to launch the shell with the provided config
}

func SetupZshShell(config Config, env []string) ([]string, error) {
	// Create a temporary ZDOTDIR for zsh
	tmpDir, err := os.MkdirTemp("", "sesh_zsh")
	if err != nil {
		return []string{}, fmt.Errorf("failed to create temp dir for zsh: %w", err)
	}
	zshrc := filepath.Join(tmpDir, ".zshrc")

	if writeErr := os.WriteFile(zshrc, []byte(config.ShellCustomizer.GetZshInitScript()), 0644); writeErr != nil {
		return []string{}, fmt.Errorf("failed to write temp zshrc: %w", writeErr)
	}
	env = append(env, fmt.Sprintf("ZDOTDIR=%s", tmpDir))

	return env, nil
}

func SetupBashShell(config Config) (*os.File, error) {
	// Create a temporary rcfile for bash
	tmpFile, err := os.CreateTemp("", "sesh_bashrc")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp bashrc: %w", err)
	}
	defer tmpFile.Close()

	if _, writeErr := tmpFile.WriteString(config.ShellCustomizer.GetBashInitScript()); writeErr != nil {
		return nil, fmt.Errorf("failed to write temp bashrc: %w", writeErr)
	}

	return tmpFile, nil
}

func SetupFallbackShell(config Config, env []string) ([]string, error) {
	tmpFile, err := os.CreateTemp("", "sesh_shellrc")
	if err != nil {
		return []string{}, fmt.Errorf("failed to create temp shellrc: %w", err)
	}
	defer tmpFile.Close()

	if _, writeErr := tmpFile.WriteString(config.ShellCustomizer.GetFallbackInitScript()); writeErr != nil {
		return []string{}, fmt.Errorf("failed to write temp shellrc: %w", writeErr)
	}

	env = append(env, fmt.Sprintf("PS1=(sesh:%s) $ ", config.ServiceName))
	env = append(env, fmt.Sprintf("ENV=%s", tmpFile.Name())) // For sh shells

	return env, nil
}

// FilterEnv removes any existing environment variables with the specified key
// This ensures we don't have duplicate environment variables
func FilterEnv(env []string, key string) []string {
	var result []string
	prefix := key + "="
	for _, item := range env {
		if len(item) < len(prefix) || item[:len(prefix)] != prefix {
			result = append(result, item)
		}
	}
	return result
}
