package main

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
)

// LaunchSubshell launches a new shell with credentials loaded
func (a *App) LaunchSubshell(serviceName string) error {
	p, err := a.Registry.GetProvider(serviceName)
	if err != nil {
		return fmt.Errorf("provider not found: %w", err)
	}

	creds, err := p.GetCredentials()
	if err != nil {
		return fmt.Errorf("failed to generate credentials: %w", err)
	}

	// Create minimal environment for the subshell
	env := os.Environ()
	
	// Add credential variables
	for key, value := range creds.Variables {
		env = removeFromEnv(env, key)
		env = append(env, fmt.Sprintf("%s=%s", key, value))
	}
	
	// Add minimal sesh variables
	env = append(env, "SESH_ACTIVE=1")
	env = append(env, fmt.Sprintf("SESH_SERVICE=%s", serviceName))
	env = append(env, "SESH_DISABLE_INTEGRATION=1")
	
	// Determine which shell to use
	shell := os.Getenv("SHELL")
	if shell == "" {
		if runtime.GOOS == "windows" {
			shell = "cmd.exe"
		} else {
			shell = "/bin/sh"
		}
	}
	
	// Create and run the shell command
	cmd := exec.Command(shell)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = env
	
	// Simple output
	fmt.Fprintf(a.Stdout, "Starting secure shell with %s credentials\n", serviceName)
	
	// Run the shell
	err = cmd.Run()
	
	// Simple exit message
	fmt.Fprintf(a.Stdout, "Exited secure shell.\n")
	
	return err
}

// removeFromEnv removes a specific environment variable from the env list
func removeFromEnv(env []string, key string) []string {
	var result []string
	prefix := key + "="
	for _, item := range env {
		if len(item) < len(prefix) || item[:len(prefix)] != prefix {
			result = append(result, item)
		}
	}
	return result
}