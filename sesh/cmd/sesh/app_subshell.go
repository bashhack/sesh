package main

import (
	"errors"
	"fmt"
	"github.com/bashhack/sesh/internal/aws"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// LaunchSubshell launches a new shell with credentials loaded
func (a *App) LaunchSubshell(serviceName string) error {
	// Check if we're already in a sesh environment to prevent nested sessions
	if os.Getenv("SESH_ACTIVE") == "1" {
		return fmt.Errorf("already in a sesh environment, nested sessions are not supported.\nPlease exit the current sesh shell first with 'exit' or Ctrl+D")
	}

	// Get provider and credentials
	p, err := a.Registry.GetProvider(serviceName)
	if err != nil {
		return fmt.Errorf("provider not found: %w", err)
	}

	creds, err := p.GetCredentials()
	if err != nil {
		return fmt.Errorf("failed to generate credentials: %w", err)
	}

	// Create environment with credentials
	env := os.Environ()

	// Add credential variables to environment
	for key, value := range creds.Variables {
		env = filterEnv(env, key)
		env = append(env, fmt.Sprintf("%s=%s", key, value))
	}

	// Add basic SESH variables
	env = append(env, "SESH_ACTIVE=1")
	env = append(env, fmt.Sprintf("SESH_SERVICE=%s", serviceName))
	env = append(env, "SESH_DISABLE_INTEGRATION=1")

	// Add session timing information
	env = append(env, fmt.Sprintf("SESH_START_TIME=%d", time.Now().Unix()))
	if !creds.Expiry.IsZero() {
		env = append(env, fmt.Sprintf("SESH_EXPIRY=%d", creds.Expiry.Unix()))
		env = append(env, fmt.Sprintf("SESH_TOTAL_DURATION=%d", creds.Expiry.Unix()-time.Now().Unix()))
	}

	// Determine which shell to use
	shell := os.Getenv("SHELL")
	if shell == "" {
		shell = "/bin/sh"
	}

	// Handle shell-specific init customization
	var cmd *exec.Cmd

	switch {
	case shell == "/bin/zsh" || filepath.Base(shell) == "zsh":
		// Create a temporary ZDOTDIR for zsh
		tmpDir, err := os.MkdirTemp("", "sesh_zsh")
		if err != nil {
			return fmt.Errorf("failed to create temp dir for zsh: %w", err)
		}
		zshrc := filepath.Join(tmpDir, ".zshrc")

		// Construct zsh init script with common functions
		if writeErr := os.WriteFile(zshrc, []byte(aws.ZshPrompt), 0644); writeErr != nil {
			return fmt.Errorf("failed to write temp zshrc: %w", writeErr)
		}
		env = append(env, fmt.Sprintf("ZDOTDIR=%s", tmpDir))
		cmd = exec.Command(shell)

	case shell == "/bin/bash" || filepath.Base(shell) == "bash":
		// Create a temporary rcfile for bash
		tmpFile, err := os.CreateTemp("", "sesh_bashrc")
		if err != nil {
			return fmt.Errorf("failed to create temp bashrc: %w", err)
		}
		defer tmpFile.Close()

		if _, writeErr := tmpFile.WriteString(aws.BashPrompt); writeErr != nil {
			return fmt.Errorf("failed to write temp bashrc: %w", writeErr)
		}
		cmd = exec.Command(shell, "--rcfile", tmpFile.Name())

	default:
		// fallback shell - create a basic script file to define functions
		tmpFile, err := os.CreateTemp("", "sesh_shellrc")
		if err != nil {
			return fmt.Errorf("failed to create temp shellrc: %w", err)
		}
		defer tmpFile.Close()

		if _, writeErr := tmpFile.WriteString(aws.FallbackPrompt); writeErr != nil {
			return fmt.Errorf("failed to write temp shellrc: %w", writeErr)
		}

		// Set environment to show the prompt
		env = append(env, fmt.Sprintf("PS1=(sesh:%s) $ ", serviceName))
		env = append(env, fmt.Sprintf("ENV=%s", tmpFile.Name())) // For sh shells

		cmd = exec.Command(shell)
	}

	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = env

	fmt.Fprintf(a.Stdout, "Starting secure shell with %s credentials\n", serviceName)
	err = cmd.Run()

	fmt.Fprintf(a.Stdout, "Exited secure shell\n")

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

// Helper function to filter environment variables
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
