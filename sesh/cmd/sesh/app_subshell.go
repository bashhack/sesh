package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
)

// LaunchSubshell launches a new shell with credentials loaded
func (a *App) LaunchSubshell(serviceName string) error {
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
		zshrcContent := fmt.Sprintf(`
export SESH_ACTIVE=1
export SESH_SERVICE=%q
PROMPT="(sesh:%s) ${PROMPT}"
`, serviceName, serviceName)
		if writeErr := os.WriteFile(zshrc, []byte(zshrcContent), 0644); writeErr != nil {
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
		bashrcContent := fmt.Sprintf(`
export SESH_ACTIVE=1
export SESH_SERVICE=%q
PS1="(sesh:%s) $PS1"
`, serviceName, serviceName)
		if _, writeErr := tmpFile.WriteString(bashrcContent); writeErr != nil {
			return fmt.Errorf("failed to write temp bashrc: %w", writeErr)
		}
		cmd = exec.Command(shell, "--rcfile", tmpFile.Name())

	default:
		// fallback shell
		env = append(env, fmt.Sprintf("PS1=(sesh:%s) $ ", serviceName))
		cmd = exec.Command(shell)
	}

	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = env

	fmt.Fprintf(a.Stdout, "Starting secure shell with %s credentials\n", serviceName)
	err = cmd.Run()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			if status, ok := exitErr.Sys().(syscall.WaitStatus); ok {
				if status.Signaled() {
					sig := status.Signal()
					if sig == syscall.SIGINT {
						// Treat Ctrl+C as a clean exit (optional UX choice)
						return nil
					}
					// Optionally print a more descriptive message
					return fmt.Errorf("subshell terminated by signal: %s", sig)
				} else {
					// Non-zero exit status
					return fmt.Errorf("subshell exited with code: %d", status.ExitStatus())
				}
			}
		}
		// Unwrap unknown exit error
		return fmt.Errorf("subshell exited with error: %w", err)
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
