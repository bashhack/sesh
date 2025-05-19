package main

import (
	"errors"
	"fmt"
	"github.com/bashhack/sesh/internal/provider"
	"github.com/bashhack/sesh/internal/subshell"
	"os"
	"os/exec"
)

// LaunchSubshell launches a new shell with credentials loaded
func (a *App) LaunchSubshell(serviceName string) error {
	if os.Getenv("SESH_ACTIVE") == "1" {
		return fmt.Errorf("already in a sesh environment, nested sessions are not supported.\nPlease exit the current sesh shell first with 'exit' or Ctrl+D")
	}

	p, err := a.Registry.GetProvider(serviceName)
	if err != nil {
		return fmt.Errorf("provider not found: %w", err)
	}

	creds, err := p.GetCredentials()
	if err != nil {
		return fmt.Errorf("failed to generate credentials: %w", err)
	}

	subshellP, ok := p.(provider.SubshellProvider)
	if !ok {
		return fmt.Errorf("provider %s does not support subshell customization", serviceName)
	}

	configInterface := subshellP.NewSubshellConfig(creds)
	config, ok := configInterface.(subshell.Config)
	if !ok {
		return fmt.Errorf("provider %s returned invalid subshell configuration", serviceName)
	}

	shellConfig, err := subshell.GetShellConfig(config, a.Stdout, a.Stderr)
	if err != nil {
		return err
	}

	var cmd *exec.Cmd

	if len(shellConfig.Args) > 0 {
		cmd = exec.Command(shellConfig.Shell, shellConfig.Args...)
	} else {
		cmd = exec.Command(shellConfig.Shell)
	}

	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = shellConfig.Env

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
