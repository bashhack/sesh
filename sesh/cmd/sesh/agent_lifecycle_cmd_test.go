package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"net"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/bashhack/sesh/internal/agent"
)

// TestMain keeps agent hardening out of the test binary: the daemon path
// runs in-process here, and hardening (no ptrace, no core dumps) is
// process-wide.
func TestMain(m *testing.M) {
	hardenProcess = func() error { return nil }
	os.Exit(m.Run())
}

func TestWriteAgentStatus(t *testing.T) {
	now := time.Date(2026, 5, 3, 9, 52, 0, 0, time.UTC)
	at := func(hh, mm, ss int) int64 { return time.Date(2026, 5, 3, hh, mm, ss, 0, time.UTC).Unix() }

	mine := agent.Build()
	if len(mine) < 12 {
		t.Fatalf("agent.Build() = %q: the test binary's own hash is needed", mine)
	}
	tests := map[string]struct {
		want string
		st   agent.StatusResponse
	}{
		"locked, never unlocked": {
			st: agent.StatusResponse{AgentPID: 4242, AgentBuild: mine},
			want: "agent: running (pid 4242)\n" +
				"build:          " + mine[:12] + "\n" +
				"state: locked\n" +
				"last unlock:    never\n",
		},
		"locked after an unlock": {
			st: agent.StatusResponse{AgentPID: 4242, AgentBuild: mine, LastUnlockUnix: at(9, 51, 22)},
			want: "agent: running (pid 4242)\n" +
				"build:          " + mine[:12] + "\n" +
				"state: locked\n" +
				"last unlock:    2026-05-03 09:51:22 (38s ago)\n",
		},
		"idle timeout comes first": {
			st: agent.StatusResponse{
				AgentPID: 4242, AgentBuild: mine, Unlocked: true,
				UnlockedAtUnix: at(9, 14, 0), LastActivityUnix: at(9, 51, 48), LocksAtUnix: at(10, 1, 48),
				IdleTimeoutSec: 600, MaxLifetimeSec: 8 * 3600,
			},
			want: "agent: running (pid 4242)\n" +
				"build:          " + mine[:12] + "\n" +
				"state: unlocked\n" +
				"unlocked since: 2026-05-03 09:14:00 (38m ago)\n" +
				"last activity:  2026-05-03 09:51:48 (12s ago)\n" +
				"auto-lock in:   9m 48s (idle timeout)\n" +
				"max lifetime:   7h 22m remaining\n",
		},
		"max lifetime comes first": {
			st: agent.StatusResponse{
				AgentPID: 4242, AgentBuild: mine, Unlocked: true,
				UnlockedAtUnix: at(2, 0, 0), LastActivityUnix: at(9, 51, 58), LocksAtUnix: at(10, 0, 0),
				IdleTimeoutSec: 600, MaxLifetimeSec: 8 * 3600,
			},
			want: "agent: running (pid 4242)\n" +
				"build:          " + mine[:12] + "\n" +
				"state: unlocked\n" +
				"unlocked since: 2026-05-03 02:00:00 (7h 52m ago)\n" +
				"last activity:  2026-05-03 09:51:58 (2s ago)\n" +
				"auto-lock in:   8m (max lifetime)\n" +
				"max lifetime:   8m remaining\n",
		},
		"idle timeout disabled": {
			st: agent.StatusResponse{
				AgentPID: 4242, AgentBuild: mine, Unlocked: true,
				UnlockedAtUnix: at(9, 30, 0), LastActivityUnix: at(9, 50, 0), LocksAtUnix: at(10, 30, 0),
				MaxLifetimeSec: 3600,
			},
			want: "agent: running (pid 4242)\n" +
				"build:          " + mine[:12] + "\n" +
				"state: unlocked\n" +
				"unlocked since: 2026-05-03 09:30:00 (22m ago)\n" +
				"last activity:  2026-05-03 09:50:00 (2m ago)\n" +
				"auto-lock in:   38m (max lifetime)\n" +
				"max lifetime:   38m remaining\n",
		},
		"both timeouts disabled": {
			st: agent.StatusResponse{
				AgentPID: 4242, AgentBuild: mine, Unlocked: true,
				UnlockedAtUnix: at(9, 30, 0), LastActivityUnix: at(9, 50, 0),
			},
			want: "agent: running (pid 4242)\n" +
				"build:          " + mine[:12] + "\n" +
				"state: unlocked\n" +
				"unlocked since: 2026-05-03 09:30:00 (22m ago)\n" +
				"last activity:  2026-05-03 09:50:00 (2m ago)\n" +
				"auto-lock in:   never (timeouts disabled)\n" +
				"max lifetime:   disabled\n",
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := writeAgentStatus(&buf, &tt.st, now); err != nil {
				t.Fatal(err)
			}
			if got := buf.String(); got != tt.want {
				t.Fatalf("status output:\n%s\nwant:\n%s", got, tt.want)
			}
		})
	}
}

func TestBuildLine(t *testing.T) {
	const a = "aaaaaaaaaaaabbbbbbbb"
	const b = "ccccccccccccdddddddd"
	tests := map[string]struct{ agentBuild, mine, want string }{
		"same build":           {a, a, "aaaaaaaaaaaa"},
		"other build":          {a, b, "aaaaaaaaaaaa (this sesh is cccccccccccc; the next command replaces it)"},
		"agent predates it":    {"", b, "unknown (older agent; the next command replaces it)"},
		"own build unreadable": {a, "", "aaaaaaaaaaaa"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if got := buildLine(tt.agentBuild, tt.mine); got != tt.want {
				t.Errorf("buildLine = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestHumanDuration(t *testing.T) {
	tests := map[time.Duration]string{
		0:                           "0s",
		-time.Second:                "0s",
		12 * time.Second:            "12s",
		38 * time.Minute:            "38m",
		2*time.Hour + 5*time.Second: "2h 5s",
		7*time.Hour + 21*time.Minute + 22*time.Second: "7h 21m 22s",
		1499 * time.Millisecond:                       "1s",
	}
	for d, want := range tests {
		if got := humanDuration(d); got != want {
			t.Errorf("humanDuration(%v) = %q, want %q", d, got, want)
		}
	}
}

func runAgentOut(t *testing.T, args ...string) string {
	t.Helper()
	app := agentTestApp()
	if err := runAgent(app, args); err != nil {
		t.Fatalf("sesh agent %s: %v", strings.Join(args, " "), err)
	}
	return app.Stdout.(*bytes.Buffer).String()
}

func TestAgentControl_NoAgentRunning(t *testing.T) {
	t.Setenv("SESH_AUTH_SOCK", tempAgentSocket(t))
	for _, cmd := range []string{"lock", "status", "stop"} {
		if got := runAgentOut(t, cmd); got != "agent: not running\n" {
			t.Errorf("sesh agent %s = %q, want not running", cmd, got)
		}
	}
}

func TestAgentControl_LockStatusStop(t *testing.T) {
	dir := t.TempDir()
	writeLightSidecar(t, dir, "correct-horse")
	startTestAgent(t)
	ks, _, err := keySourceFromAgent(dir, fixedPrompt("correct-horse"))
	if err != nil || ks == nil {
		t.Fatalf("unlock agent: %v", err)
	}
	closeKeySource(t, ks)

	if got := runAgentOut(t, "status"); !strings.Contains(got, "state: unlocked\n") {
		t.Fatalf("status after unlock:\n%s", got)
	}
	if got := runAgentOut(t, "lock"); got != "agent locked\n" {
		t.Fatalf("lock = %q", got)
	}
	if got := runAgentOut(t, "status"); !strings.Contains(got, "state: locked\n") {
		t.Fatalf("status after lock:\n%s", got)
	}
	if got := runAgentOut(t, "stop"); got != "agent stopped\n" {
		t.Fatalf("stop = %q", got)
	}
	if got := runAgentOut(t, "status"); got != "agent: not running\n" {
		t.Fatalf("status after stop = %q", got)
	}
}

func TestAgentControl_RejectsArguments(t *testing.T) {
	err := runAgent(agentTestApp(), []string{"lock", "now"})
	if err == nil || !strings.Contains(err.Error(), "takes no arguments") {
		t.Fatalf("err = %v, want takes-no-arguments", err)
	}
}

func TestAgentDaemon_TimeoutsFromEnvAndFlags(t *testing.T) {
	sockPath := tempAgentSocket(t)
	t.Setenv("SESH_AUTH_SOCK", sockPath)
	t.Setenv("SESH_AGENT_IDLE_TIMEOUT", "30s")
	t.Setenv("SESH_AGENT_MAX_LIFETIME", "2h")

	hardened := false
	orig := hardenProcess
	hardenProcess = func() error { hardened = true; return nil }
	t.Cleanup(func() { hardenProcess = orig })

	done := make(chan error, 1)
	go func() { done <- runAgent(agentTestApp(), []string{"--socket", sockPath, "--max-lifetime", "45m"}) }()
	waitForSocketBound(t, sockPath)

	conn, err := agent.DialExisting()
	if err != nil {
		t.Fatal(err)
	}
	st, err := agent.Status(conn)
	if err != nil {
		t.Fatal(err)
	}
	if st.IdleTimeoutSec != 30 || st.MaxLifetimeSec != 45*60 {
		t.Fatalf("timeouts = idle %ds, max %ds; want 30s from env and 45m from the flag", st.IdleTimeoutSec, st.MaxLifetimeSec)
	}
	if err := agent.Stop(conn); err != nil {
		t.Fatal(err)
	}
	closeAgentConn(conn)
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("runAgent: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("daemon still running after stop")
	}
	if !hardened {
		t.Fatal("daemon did not apply process hardening")
	}
}

func TestAgentDaemon_RejectsBadTimeouts(t *testing.T) {
	tests := map[string]struct {
		env     string
		wantSub string
		args    []string
	}{
		"unparseable env": {env: "soon", wantSub: "SESH_AGENT_IDLE_TIMEOUT"},
		"negative env":    {env: "-1m", wantSub: "must not be negative"},
		"negative flag":   {args: []string{"--idle-timeout", "-1s"}, wantSub: "must not be negative"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Setenv("SESH_AUTH_SOCK", tempAgentSocket(t))
			t.Setenv("SESH_AGENT_IDLE_TIMEOUT", tt.env)
			err := runAgent(agentTestApp(), tt.args)
			if err == nil || !strings.Contains(err.Error(), tt.wantSub) {
				t.Fatalf("err = %v, want %q", err, tt.wantSub)
			}
		})
	}
}

func TestAgentDaemon_StartupErrorIsTimestamped(t *testing.T) {
	t.Setenv("SESH_AUTH_SOCK", tempAgentSocket(t))
	t.Setenv("SESH_AGENT_IDLE_TIMEOUT", "soon")
	app := agentTestApp()
	stderr := app.Stderr.(*bytes.Buffer)
	run(app, []string{"sesh", "agent"})

	got := strings.TrimSpace(stderr.String())
	if !strings.Contains(got, "SESH_AGENT_IDLE_TIMEOUT") {
		t.Fatalf("stderr = %q, want the startup error", got)
	}
	stamped := regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(Z|[+-]\d{2}:\d{2}) `)
	for line := range strings.SplitSeq(got, "\n") {
		if !stamped.MatchString(line) {
			t.Errorf("line without a timestamp: %q", line)
		}
	}
}

func TestAgentDaemon_RefusesWhenHardeningFails(t *testing.T) {
	sockPath := tempAgentSocket(t)
	orig := hardenProcess
	hardenProcess = func() error { return errors.New("deny debugger attach: not permitted") }
	t.Cleanup(func() { hardenProcess = orig })

	err := runAgent(agentTestApp(), []string{"--socket", sockPath})
	if err == nil || !strings.Contains(err.Error(), "harden agent: deny debugger attach") {
		t.Fatalf("err = %v, want the hardening failure", err)
	}
	if _, err := os.Stat(sockPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("socket exists after a refused start: %v", err)
	}
}

// startRefusingAgent acks hello on every connection and answers every
// other request with internal_error.
func startRefusingAgent(t *testing.T) {
	t.Helper()
	sock := tempAgentSocket(t)
	lis, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := lis.Close(); err != nil {
			t.Errorf("close fake agent: %v", err)
		}
	})
	go func() {
		for {
			c, err := lis.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close() //nolint:errcheck // fake agent teardown
				r := bufio.NewReader(c)
				for {
					line, err := r.ReadBytes('\n')
					if err != nil {
						return
					}
					var env struct {
						Type string `json:"type"`
					}
					if json.Unmarshal(line, &env) != nil {
						return
					}
					var resp any = agent.ErrorResponse{Type: agent.TypeError, Version: agent.ProtocolVersion, Code: agent.ErrCodeInternal, Message: "boom"}
					if env.Type == agent.TypeHello {
						resp = agent.HelloResponse{Type: agent.TypeHelloAck, Version: agent.ProtocolVersion}
					}
					b, _ := json.Marshal(resp) //nolint:errcheck // fixed shapes always marshal
					if _, err := c.Write(append(b, '\n')); err != nil {
						return
					}
				}
			}()
		}
	}()
	t.Setenv("SESH_AUTH_SOCK", sock)
}

func TestAgentControl_ReportsAgentErrors(t *testing.T) {
	startRefusingAgent(t)
	for _, cmd := range []string{"lock", "status", "stop"} {
		err := runAgent(agentTestApp(), []string{cmd})
		if err == nil || !strings.Contains(err.Error(), cmd+": internal_error: boom") {
			t.Errorf("sesh agent %s err = %v, want the agent's error", cmd, err)
		}
	}
}

func TestAgentDaemon_RejectsBadMaxLifetime(t *testing.T) {
	t.Setenv("SESH_AUTH_SOCK", tempAgentSocket(t))
	t.Setenv("SESH_AGENT_MAX_LIFETIME", "forever")
	err := runAgent(agentTestApp(), nil)
	if err == nil || !strings.Contains(err.Error(), "SESH_AGENT_MAX_LIFETIME") {
		t.Fatalf("err = %v, want SESH_AGENT_MAX_LIFETIME", err)
	}
}
