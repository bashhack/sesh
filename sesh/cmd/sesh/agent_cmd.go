package main

import (
	"context"
	"flag"
	"fmt"

	"github.com/bashhack/sesh/internal/agent"
)

// runAgent is the entry point for the `sesh agent` subcommand. It runs
// the agent daemon in the foreground until SIGTERM/SIGINT arrives, at
// which point the listener closes and the socket file is removed.
func runAgent(app *App, args []string) error {
	fs := flag.NewFlagSet("agent", flag.ContinueOnError)
	fs.SetOutput(app.Stderr)
	socket := fs.String("socket", "", "Override the canonical socket path. Defaults to <cache>/sesh/agent.sock.")
	if err := fs.Parse(args); err != nil {
		return err
	}

	sockPath := *socket
	if sockPath == "" {
		var err error
		sockPath, err = agent.SocketPath()
		if err != nil {
			return fmt.Errorf("resolve socket path: %w", err)
		}
	}

	srv, err := agent.Listen(sockPath)
	if err != nil {
		return fmt.Errorf("start agent: %w", err)
	}
	// Banner write to stderr is best-effort — a closed parent stderr
	// shouldn't kill an otherwise healthy daemon.
	_, _ = fmt.Fprintf(app.Stderr, "sesh-agent listening at %s\n", srv.SocketPath()) //nolint:errcheck // best-effort banner

	if err := srv.Run(context.Background()); err != nil {
		return fmt.Errorf("agent: %w", err)
	}
	return nil
}
