package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bashhack/sesh/internal/agent"
	"github.com/bashhack/sesh/internal/config"
	"github.com/bashhack/sesh/internal/vault"
)

// useConfigFile points XDG_CONFIG_HOME at a temp dir, clears sesh's setting
// env vars, writes body as config.toml (unless empty), and returns its path.
func useConfigFile(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	for _, k := range []string{config.EnvDBPath, config.EnvClipboardTimeout, config.EnvAgentIdleTimeout, config.EnvAgentMaxLifetime, config.EnvAuditRetentionDays} {
		t.Setenv(k, "")
	}
	path := filepath.Join(dir, "sesh", "config.toml")
	if body == "" {
		return path
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestSubcommand_OnlyTheFirstArgument(t *testing.T) {
	tests := map[string]struct {
		want      string
		args      []string
		needStore bool
	}{
		"agent subcommand":         {"agent", []string{"sesh", "agent", "status"}, false},
		"config subcommand":        {"config", []string{"sesh", "config"}, false},
		"entry named agent":        {"", []string{"sesh", "-service", "password", "-action", "get", "-service-name", "agent"}, true},
		"entry named config, last": {"", []string{"sesh", "-service", "totp", "-service-name", "config"}, true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if got, _ := subcommand(tt.args); got != tt.want {
				t.Errorf("subcommand = %q, want %q", got, tt.want)
			}
			if got := needsCredentialStore(tt.args); got != tt.needStore {
				t.Errorf("needsCredentialStore = %v, want %v", got, tt.needStore)
			}
		})
	}
}

func TestRunConfig_ShowsValuesAndSources(t *testing.T) {
	path := useConfigFile(t, "clipboard_timeout = \"45s\"\n[agent]\nmax_lifetime = \"2h\"\n[audit]\nretention_days = 0\n")
	t.Setenv(config.EnvDBPath, "/tmp/sesh-test/vault.db")
	app := agentTestApp()
	if err := runConfig(app, nil); err != nil {
		t.Fatal(err)
	}
	got := app.Stdout.(*bytes.Buffer).String()
	for _, want := range []string{
		"config file: " + path + "\n",
		"clipboard_timeout     45s           (config file)\n",
		"agent.idle_timeout    10m           (default)\n",
		"agent.max_lifetime    2h            (config file)\n",
		"audit.retention_days  0 (keep all)  (config file)\n",
		"db_path               /tmp/sesh-test/vault.db\n                      (environment: SESH_DB_PATH)\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("output missing %q:\n%s", want, got)
		}
	}
}

func TestRunConfig_NoFile(t *testing.T) {
	path := useConfigFile(t, "")
	app := agentTestApp()
	if err := runConfig(app, nil); err != nil {
		t.Fatal(err)
	}
	if got := app.Stdout.(*bytes.Buffer).String(); !strings.Contains(got, "config file: "+path+" (not found; using defaults)") {
		t.Errorf("output = %q", got)
	}
}

func TestRunConfig_ReportsABrokenFile(t *testing.T) {
	path := useConfigFile(t, "clipboard_timeout = \"soon\"\n")
	app := agentTestApp()
	err := runConfig(app, nil)
	if err == nil || !strings.Contains(err.Error(), `clipboard_timeout in `+path+` = "soon"`) {
		t.Fatalf("err = %v, want the bad setting named with the file", err)
	}
	if got := app.Stdout.(*bytes.Buffer).String(); !strings.Contains(got, "config file: "+path) {
		t.Errorf("stdout = %q, want the config file path", got)
	}
}

func TestDuration(t *testing.T) {
	for d, want := range map[time.Duration]string{
		30 * time.Second: "30s", 90 * time.Second: "1m30s", 10 * time.Minute: "10m",
		8 * time.Hour: "8h", 90 * time.Minute: "1h30m", 0: "0 (off)",
	} {
		if got := duration(d); got != want {
			t.Errorf("duration(%v) = %q, want %q", d, got, want)
		}
	}
}

func TestOpenSQLiteStore_ConfigFileAlone(t *testing.T) {
	vaultPath := filepath.Join(t.TempDir(), "nested", "vault.db")
	useConfigFile(t, "db_path = \""+vaultPath+"\"\n")
	t.Setenv("SESH_MASTER_PASSWORD", "config-only-1234")

	cfg, err := settings()
	if err != nil {
		t.Fatal(err)
	}
	kc, closer, err := buildProvider(cfg)
	if err != nil {
		t.Fatalf("buildProvider: %v", err)
	}
	if closer == nil {
		t.Fatal("buildProvider returned no closer for the vault the config file names")
	}
	if err := kc.Put(vault.Key{Kind: vault.KindPassword, Service: "x"}, []byte("v")); err != nil {
		t.Fatal(err)
	}
	if err := closer.Close(); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{vaultPath, filepath.Join(filepath.Dir(vaultPath), sidecarFile)} {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("%s not created: %v", p, err)
		}
	}
}

func TestAgentDaemon_TimeoutsFromConfigFile(t *testing.T) {
	useConfigFile(t, "[agent]\nidle_timeout = \"20s\"\nmax_lifetime = \"3h\"\n")
	sockPath := tempAgentSocket(t)
	t.Setenv("SESH_AUTH_SOCK", sockPath)

	done := make(chan error, 1)
	go func() { done <- runAgent(agentTestApp(), []string{"--socket", sockPath}) }()
	waitForSocketBound(t, sockPath)
	conn, err := agent.DialExisting()
	if err != nil {
		t.Fatal(err)
	}
	st, err := agent.Status(conn)
	if err != nil {
		t.Fatal(err)
	}
	if st.IdleTimeoutSec != 20 || st.MaxLifetimeSec != 3*3600 {
		t.Errorf("timeouts = idle %ds, max %ds; want 20s and 3h from the config file", st.IdleTimeoutSec, st.MaxLifetimeSec)
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
}
