package subshell

import (
	"errors"
	"fmt"
	"io"
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

func Launch(config Config, stdout, stderr io.Writer) error {
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
	var shellSetupErr error

	switch {
	case shell == "/bin/zsh" || filepath.Base(shell) == "zsh":
		cmd, shellSetupErr = setupZshShell(shell, config, env)
	case shell == "/bin/bash" || filepath.Base(shell) == "bash":
		cmd, shellSetupErr = setupBashShell(shell, config, env)
	default:
		cmd, shellSetupErr = setupFallbackShell(shell, config, env)
	}
	if shellSetupErr != nil {
		return fmt.Errorf("failed to set up shell: %w", shellSetupErr)
	}

	// Write debug info
	debugFile, _ := os.OpenFile("/tmp/sesh_debug.txt", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if debugFile != nil {
		defer debugFile.Close()
		fmt.Fprintf(debugFile, "=== SESH DEBUG ===\n")
		fmt.Fprintf(debugFile, "Shell: %s\n", shell)
		fmt.Fprintf(debugFile, "Types - stdout: %T, stderr: %T\n", stdout, stderr)
		fmt.Fprintf(debugFile, "os.Stdout: %T, os.Stderr: %T\n", os.Stdout, os.Stderr)
		fmt.Fprintf(debugFile, "Environment variables:\n")
		for _, envVar := range env {
			if len(envVar) >= 8 && envVar[:8] == "ZDOTDIR=" {
				zdir := envVar[8:]
				fmt.Fprintf(debugFile, "ZDOTDIR set to: %s\n", zdir)
				zshrcPath := filepath.Join(zdir, ".zshrc")
				fmt.Fprintf(debugFile, "Looking for .zshrc at: %s\n", zshrcPath)
				fileContent, err := os.ReadFile(zshrcPath)
				if err != nil {
					fmt.Fprintf(debugFile, "Error reading .zshrc: %v\n", err)
				} else {
					fmt.Fprintf(debugFile, ".zshrc content begins:\n")
					fmt.Fprintf(debugFile, "%s\n", string(fileContent))
					fmt.Fprintf(debugFile, ".zshrc content ends\n")
				}
			}
		}
		fmt.Fprintf(debugFile, "Command args: %v\n", cmd.Args)
	}

	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = env

	// Print the starting message including the welcome message from the customizer
	fmt.Fprintf(stdout, "Starting secure shell with %s credentials\n", config.ServiceName)
	if config.ShellCustomizer != nil {
		welcomeMsg := config.ShellCustomizer.GetWelcomeMessage()
		if welcomeMsg != "" {
			fmt.Fprintf(stdout, "%s\n", welcomeMsg)
		}
	}
	
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

	// Write debug info
	debugFile, _ := os.OpenFile("/tmp/sesh_debug.txt", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if debugFile != nil {
		defer debugFile.Close()
		fmt.Fprintf(debugFile, "=== SETUP ZSH SHELL DEBUG ===\n")
		fmt.Fprintf(debugFile, "tmpDir: %s\n", tmpDir)
		fmt.Fprintf(debugFile, "zshrc: %s\n", zshrc)
		initScript := config.ShellCustomizer.GetZshInitScript()
		fmt.Fprintf(debugFile, "Init script length: %d\n", len(initScript))
		if len(initScript) > 100 {
			fmt.Fprintf(debugFile, "First 100 chars: %s\n", initScript[:100])
		} else {
			fmt.Fprintf(debugFile, "Full init script: %s\n", initScript)
		}
	}

	// Construct zsh init script with common functions
	if writeErr := os.WriteFile(zshrc, []byte(config.ShellCustomizer.GetZshInitScript()), 0644); writeErr != nil {
		return nil, fmt.Errorf("failed to write temp zshrc: %w", writeErr)
	}
	
	// Verify the .zshrc was written properly
	if debugFile != nil {
		fileContent, err := os.ReadFile(zshrc)
		if err != nil {
			fmt.Fprintf(debugFile, "Error reading back .zshrc: %v\n", err)
		} else {
			fmt.Fprintf(debugFile, "Actual .zshrc content after write (first 100 chars): %s\n", string(fileContent)[:100])
			fmt.Fprintf(debugFile, "Actual .zshrc file size: %d bytes\n", len(fileContent))
		}
	}
	
	env = append(env, fmt.Sprintf("ZDOTDIR=%s", tmpDir))
	
	// From the original working code: just run shell without any flags
	return exec.Command(shell), nil
}

func setupBashShell(shell string, config Config, env []string) (*exec.Cmd, error) {
	// Create a temporary rcfile for bash
	tmpFile, err := os.CreateTemp("", "sesh_bashrc")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp bashrc: %w", err)
	}
	defer tmpFile.Close()

	if _, writeErr := tmpFile.WriteString(config.ShellCustomizer.GetBashInitScript()); writeErr != nil {
		return nil, fmt.Errorf("failed to write temp bashrc: %w", writeErr)
	}
	return exec.Command(shell, "--rcfile", tmpFile.Name()), nil
}

func setupFallbackShell(shell string, config Config, env []string) (*exec.Cmd, error) {
	// fallback shell - create a basic script file to define functions
	tmpFile, err := os.CreateTemp("", "sesh_shellrc")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp shellrc: %w", err)
	}
	defer tmpFile.Close()

	if _, writeErr := tmpFile.WriteString(config.ShellCustomizer.GetFallbackInitScript()); writeErr != nil {
		return nil, fmt.Errorf("failed to write temp shellrc: %w", writeErr)
	}

	// Set the environment to show the prompt
	env = append(env, fmt.Sprintf("PS1=%s$ ", config.ShellCustomizer.GetPromptPrefix()))
	env = append(env, fmt.Sprintf("ENV=%s", tmpFile.Name())) // For sh shells

	return exec.Command(shell), nil
}

// filterEnv removes any existing environment variables with the specified key
// This ensures we don't have duplicate environment variables
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
