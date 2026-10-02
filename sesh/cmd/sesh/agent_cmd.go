package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/bashhack/sesh/internal/agent"
)

// hardenProcess applies agent.Harden. Tests replace it: the daemon path runs
// inside the test binary, and hardening is process-wide.
var hardenProcess = agent.Harden

// runAgent is the entry point for `sesh agent`. With no subcommand it runs
// the daemon in the foreground until SIGTERM/SIGINT or a stop request.
// `lock`, `status`, and `stop` talk to a running agent and never start
// one.
func runAgent(app *App, args []string) error {
	if len(args) > 0 {
		switch args[0] {
		case "lock", "status", "stop":
			if len(args) > 1 {
				return fmt.Errorf("sesh agent %s takes no arguments, got %q", args[0], strings.Join(args[1:], " "))
			}
			return runAgentControl(app, args[0], time.Now())
		}
	}
	return runAgentDaemon(app, args)
}

func runAgentDaemon(app *App, args []string) error {
	// A spawned daemon's stderr is the agent log, so everything written to
	// it gets the log's timestamps, including the error run prints through
	// fatal (same *App) if startup fails.
	app.Stderr = agent.TimestampLines(app.Stderr)
	// The daemon reads its own settings, from the environment of the sesh
	// command that started it and the config file.
	st, err := settings()
	if err != nil {
		return err
	}
	idleDefault, maxDefault := st.AgentIdleTimeout.Value, st.AgentMaxLifetime.Value

	fs := flag.NewFlagSet("agent", flag.ContinueOnError)
	fs.SetOutput(app.Stderr)
	socket := fs.String("socket", "", "Override the canonical socket path. Defaults to <cache>/sesh/agent.sock.")
	idle := fs.Duration("idle-timeout", idleDefault, "Lock after this long without use; 0 disables. Config: agent.idle_timeout; env: SESH_AGENT_IDLE_TIMEOUT.")
	maxLife := fs.Duration("max-lifetime", maxDefault, "Lock this long after each unlock, even if in use; 0 disables. Config: agent.max_lifetime; env: SESH_AGENT_MAX_LIFETIME.")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *idle < 0 || *maxLife < 0 {
		return fmt.Errorf("--idle-timeout and --max-lifetime must not be negative")
	}

	sockPath := *socket
	if sockPath == "" {
		var err error
		sockPath, err = agent.SocketPath()
		if err != nil {
			return fmt.Errorf("resolve socket path: %w", err)
		}
	}

	// Applied here, in the daemon only: these settings are process-wide,
	// and tests run the server inside the test binary. An agent that
	// can't protect its memory doesn't start; the CLI then falls back to
	// prompting on every run.
	if err := hardenProcess(); err != nil {
		return fmt.Errorf("harden agent: %w", err)
	}

	srv, err := agent.Listen(sockPath,
		agent.WithIdleTimeout(*idle),
		agent.WithMaxLifetime(*maxLife),
		agent.WithLockedKeyMemory(),
		agent.WithExitOnAutoLock(),
	)
	if err != nil {
		return fmt.Errorf("start agent: %w", err)
	}
	if err := srv.Run(context.Background()); err != nil {
		return fmt.Errorf("agent: %w", err)
	}
	return nil
}

// runAgentControl runs lock, status, or stop against a running agent.
// No agent running is reported, not treated as an error.
func runAgentControl(app *App, cmd string, now time.Time) error {
	conn, err := agent.DialExisting()
	if err != nil {
		if agent.IsNotRunning(err) {
			_, err := fmt.Fprintln(app.Stdout, "agent: not running")
			return err
		}
		return fmt.Errorf("connect to agent: %w", err)
	}
	defer closeAgentConn(conn)

	switch cmd {
	case "lock":
		if err := agent.Lock(conn); err != nil {
			return fmt.Errorf("lock: %w", err)
		}
		_, err = fmt.Fprintln(app.Stdout, "agent locked")
	case "stop":
		if err := agent.Stop(conn); err != nil {
			return fmt.Errorf("stop: %w", err)
		}
		_, err = fmt.Fprintln(app.Stdout, "agent stopped")
	case "status":
		st, serr := agent.Status(conn)
		if serr != nil {
			return fmt.Errorf("status: %w", serr)
		}
		err = writeAgentStatus(app.Stdout, &st, now)
	}
	return err
}

// writeAgentStatus renders a status reply for people. Times are shown in
// now's location.
func writeAgentStatus(w io.Writer, st *agent.StatusResponse, now time.Time) error {
	var b strings.Builder
	fmt.Fprintf(&b, "agent: running (pid %d)\n", st.AgentPID)
	line := func(label, value string) { fmt.Fprintf(&b, "%-16s%s\n", label+":", value) }
	line("build", buildLine(st.AgentBuild, agent.Build()))

	if !st.Unlocked {
		b.WriteString("state: locked\n")
		if st.LastUnlockUnix == 0 {
			line("last unlock", "never")
		} else {
			line("last unlock", stamp(st.LastUnlockUnix, now))
		}
		_, err := io.WriteString(w, b.String())
		return err
	}

	b.WriteString("state: unlocked\n")
	line("unlocked since", stamp(st.UnlockedAtUnix, now))
	line("last activity", stamp(st.LastActivityUnix, now))
	if st.LocksAtUnix == 0 {
		line("auto-lock in", "never (timeouts disabled)")
	} else {
		reason := "max lifetime"
		if st.IdleTimeoutSec > 0 && st.LocksAtUnix == st.LastActivityUnix+st.IdleTimeoutSec {
			reason = "idle timeout"
		}
		line("auto-lock in", fmt.Sprintf("%s (%s)", humanDuration(time.Unix(st.LocksAtUnix, 0).Sub(now)), reason))
	}
	if st.MaxLifetimeSec > 0 {
		left := time.Unix(st.UnlockedAtUnix+st.MaxLifetimeSec, 0).Sub(now)
		line("max lifetime", humanDuration(left)+" remaining")
	} else {
		line("max lifetime", "disabled")
	}
	_, err := io.WriteString(w, b.String())
	return err
}

// stamp formats a Unix time as "2006-01-02 15:04:05 (38m ago)".
func stamp(unix int64, now time.Time) string {
	t := time.Unix(unix, 0).In(now.Location())
	return fmt.Sprintf("%s (%s ago)", t.Format(time.DateTime), humanDuration(now.Sub(t)))
}

// buildLine describes the agent's build next to this sesh's. A mismatch
// means sesh was upgraded since the agent started; the next command that
// needs the agent replaces it.
func buildLine(agentBuild, mine string) string {
	short := func(b string) string { return b[:min(12, len(b))] }
	switch {
	case agentBuild == "":
		return "unknown (older agent; the next command replaces it)"
	case mine == "" || agentBuild == mine:
		return short(agentBuild)
	default:
		return short(agentBuild) + " (this sesh is " + short(mine) + "; the next command replaces it)"
	}
}

// humanDuration renders d to the second as "7h 21m 22s", leaving out zero
// units ("38m", "2h 5s"). Zero and negative durations render as "0s".
func humanDuration(d time.Duration) string {
	d = d.Round(time.Second)
	if d <= 0 {
		return "0s"
	}
	var parts []string
	for _, u := range []struct {
		name string
		size time.Duration
	}{{"h", time.Hour}, {"m", time.Minute}, {"s", time.Second}} {
		if n := d / u.size; n > 0 {
			parts = append(parts, fmt.Sprintf("%d%s", n, u.name))
			d -= n * u.size
		}
	}
	return strings.Join(parts, " ")
}
