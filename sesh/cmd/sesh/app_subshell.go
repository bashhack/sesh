package main

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"

	"github.com/bashhack/sesh/internal/provider"
	"github.com/bashhack/sesh/internal/subshell"
)

// LaunchSubshell opens a shell with p's credentials and waits for it to
// end. release is called once the credentials are in hand, before the
// shell starts, to let go of the vault (and, without the agent, its key),
// which the shell, open for hours perhaps, doesn't need.
//
// The shell's exit status is sesh's. A hangup (the terminal closing) is
// passed on to the shell, and a request to stop as a hangup, since an
// interactive shell ignores one; the startup files sesh wrote are removed
// once it has ended.
func (a *App) LaunchSubshell(p provider.ServiceProvider, release func()) error {
	if os.Getenv("SESH_ACTIVE") == "1" {
		return fmt.Errorf("already in a sesh environment, nested sessions are not supported.\nPlease exit the current sesh shell first with 'exit' or Ctrl+D")
	}
	serviceName := p.Name()

	// Validate request early to fail fast
	if err := p.ValidateRequest(); err != nil {
		return err
	}

	creds, err := p.GetCredentials()
	if err != nil {
		return fmt.Errorf("failed to generate credentials: %w", err)
	}
	if release != nil {
		release()
	}

	subshellP, ok := p.(provider.SubshellProvider)
	if !ok {
		return fmt.Errorf("provider %s does not support subshell customization", serviceName)
	}
	config, ok := subshellP.NewSubshellConfig(&creds).(subshell.Config)
	if !ok {
		return fmt.Errorf("provider %s returned invalid subshell configuration", serviceName)
	}
	shellConfig, err := subshell.GetShellConfig(config)
	if err != nil {
		return err
	}
	if shellConfig.Cleanup != nil {
		defer shellConfig.Cleanup()
	}

	cmd := exec.Command(shellConfig.Shell, shellConfig.Args...) //nolint:gosec // the shell is $SHELL: starting the user's shell is the point
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.Env = shellConfig.Env

	if _, err := fmt.Fprintf(a.Stdout, "Starting secure shell with %s credentials\n", serviceName); err != nil {
		return fmt.Errorf("failed to write to stdout: %w", err)
	}
	err = runChildStoppedBy(cmd, nil, syscall.SIGHUP)
	if _, printErr := fmt.Fprintf(a.Stdout, "Exited secure shell\n"); printErr != nil && err == nil {
		err = fmt.Errorf("failed to write to stdout: %w", printErr)
	}
	return err
}
