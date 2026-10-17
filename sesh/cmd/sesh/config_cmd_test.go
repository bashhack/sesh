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
	"github.com/bashhack/sesh/internal/database"
	"github.com/bashhack/sesh/internal/vault"
)

// useConfigFile points XDG_CONFIG_HOME at a temp dir, clears sesh's setting
// env vars, writes body as config.toml (unless empty), and returns its path.
func useConfigFile(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	for _, k := range []string{config.EnvDBPath, config.EnvClipboardTimeout, config.EnvAgentIdleTimeout, config.EnvAgentMaxLifetime, config.EnvAuditRetentionDays, config.EnvBackupEveryDays, config.EnvBackupKeep, config.EnvBackupDir, config.EnvTrashKeepDays, config.EnvHistoryKeep, config.EnvHealthOldAfterDays, config.EnvUILockOnQuit, config.EnvAgentLockOnSleep, config.EnvAgentLockOnScreen, config.EnvSyncDir, config.EnvSyncName} {
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
	for name, tt := range map[string]struct {
		want string
		args []string
	}{
		"agent subcommand":         {"agent", []string{"sesh", "agent", "status"}},
		"config subcommand":        {"config", []string{"sesh", "config"}},
		"entry named agent":        {"copy", []string{"sesh", "copy", "agent"}},
		"entry named config, last": {"show", []string{"sesh", "show", "--reveal", "config"}},
		"no command":               {"", []string{"sesh", "--help"}},
	} {
		t.Run(name, func(t *testing.T) {
			if got, _ := subcommand(tt.args); got != tt.want {
				t.Errorf("subcommand = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRunConfig_ShowsValuesAndSources(t *testing.T) {
	path := useConfigFile(t, "clipboard_timeout = \"45s\"\n[agent]\nmax_lifetime = \"2h\"\n[audit]\nretention_days = 0\n[master_password]\nmemory = \"512MiB\"\n")
	t.Setenv(config.EnvDBPath, "/tmp/sesh-test/vault.db")
	t.Setenv(config.EnvKDFTime, "4")
	t.Setenv(config.EnvKDFThreads, "")
	t.Setenv(config.EnvKDFMemory, "")
	app := agentTestApp()
	if err := runConfig(app, nil); err != nil {
		t.Fatal(err)
	}
	got := app.Stdout.(*bytes.Buffer).String()
	for _, want := range []string{
		"config file: " + path + "\n",
		"clipboard_timeout          45s           (config file)\n",
		"agent.idle_timeout         10m           (default)\n",
		"agent.max_lifetime         2h            (config file)\n",
		"audit.retention_days       0 (keep all)  (config file)\n",
		"master_password.memory     512MiB        (config file)\n",
		"master_password.time       4             (environment: SESH_KDF_TIME)\n",
		"master_password.threads    4             (default)\n",
		"db_path                    /tmp/sesh-test/vault.db\n                           (environment: SESH_DB_PATH)\n",
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
	if got := app.Stdout.(*bytes.Buffer).String(); !strings.Contains(got, "config file: "+path+" (not found; using defaults: changing a setting makes it)") {
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

// sesh config set writes the file; "" puts the default back; lowering a keep setting asks, or needs --force.
func TestRunConfig_Set(t *testing.T) {
	path := useConfigFile(t, "[history]\nkeep = 10\n")
	read := func() string {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	app, _ := cliApp("", false)
	if out, _, err := runCLI(app, runConfig, "set", "clipboard_timeout", "15s"); err != nil || !strings.Contains(out, "✅ Set clipboard_timeout to 15s") || !strings.Contains(read(), `clipboard_timeout = "15s"`) {
		t.Errorf("set: %q, %v\n%s", out, err, read())
	}
	app, _ = cliApp("", false)
	if _, _, err := runCLI(app, runConfig, "set", "history.keep", "3"); err == nil || !strings.Contains(err.Error(), "beyond its newest 3 will be deleted for good") || !strings.Contains(err.Error(), "--force") || !strings.Contains(read(), "keep = 10") {
		t.Errorf("lowering without a terminal: %v\n%s", err, read())
	}
	app, _ = cliApp("n\n", true)
	if _, errOut, err := runCLI(app, runConfig, "set", "history.keep", "3"); err != nil || !strings.Contains(errOut, "Nothing changed") || !strings.Contains(read(), "keep = 10") {
		t.Errorf("lowering, answered no: %q, %v", errOut, err)
	}
	app, _ = cliApp("y\n", true)
	if _, _, err := runCLI(app, runConfig, "set", "history.keep", "3"); err != nil || !strings.Contains(read(), "keep = 3") {
		t.Errorf("lowering, answered yes: %v\n%s", err, read())
	}
	app, _ = cliApp("", false)
	if out, _, err := runCLI(app, runConfig, "set", "history.keep", "", "--force"); err != nil || !strings.Contains(out, "Took history.keep out of") || strings.Contains(read(), "keep =") {
		t.Errorf("back to the default: %q, %v\n%s", out, err, read())
	}
	app, _ = cliApp("", false)
	if out, _, err := runCLI(app, runConfig, "set", "history.keep", ""); err != nil || !strings.Contains(out, "isn't in the config file: it's at its default, 10, already") {
		t.Errorf("the default again: %q, %v", out, err)
	}
	app, _ = cliApp("", false)
	if _, _, err := runCLI(app, runConfig, "set", "sync.dir", "~/sync"); err != nil {
		t.Fatal(err)
	}
	app, _ = cliApp("", false)
	if out, _, err := runCLI(app, runConfig, "set", "sync.dir", ""); err != nil || !strings.Contains(out, "Took sync.dir out of") || strings.Contains(out, "default") {
		t.Errorf("a setting with no default, taken out: %q, %v", out, err)
	}
	app, _ = cliApp("", false)
	if out, _, err := runCLI(app, runConfig, "set", "agent.lock_on_sleep", "OFF"); err != nil || !strings.Contains(out, "Set agent.lock_on_sleep to off in") || !strings.Contains(read(), "lock_on_sleep = false") {
		t.Errorf("OFF: %q, %v\n%s", out, err, read())
	}
	app, _ = cliApp("", false)
	if out, _, err := runCLI(app, runConfig, "set", "history.keep", "+12"); err != nil || !strings.Contains(out, "Set history.keep to 12") || !strings.Contains(read(), "keep = 12\n") {
		t.Errorf("+12: %q, %v\n%s", out, err, read())
	}
	t.Setenv(config.EnvTrashKeepDays, "7")
	for args, wantSub := range map[string]string{
		"set nope 1":                 "nope isn't a setting; sesh config lists them",
		"set db_path /tmp/x.db":      "move the vault's files first",
		"set trash.keep_days 3":      "set by SESH_TRASH_KEEP_DAYS",
		"set clipboard_timeout soon": "clipboard_timeout",
		"set clipboard_timeout":      "name the setting and its value",
		"frobnicate":                 `sesh config takes set, or nothing, not "frobnicate"`,
	} {
		app, _ := cliApp("", false)
		if _, _, err := runCLI(app, runConfig, strings.Fields(args)...); err == nil || !strings.Contains(err.Error(), wantSub) {
			t.Errorf("%s: %v, want %q", args, err, wantSub)
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
	store, err := openSQLiteStoreWith(cfg)
	if err != nil {
		t.Fatalf("open the vault the config file names: %v", err)
	}
	if err := store.Put(vault.Key{Kind: vault.KindPassword, Service: "x"}, []byte("v")); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ReadUnlockMaterial(vaultPath); err != nil {
		t.Errorf("the vault wasn't created: %v", err)
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

// The configured Argon2id settings reach encrypted exports.
func TestAppSettings_EncryptedExportsUseTheConfiguredKDF(t *testing.T) {
	useConfigFile(t, "[master_password]\nmemory = \"20MiB\"\n")
	t.Setenv(config.EnvKDFMemory, "")
	cfg, err := settings()
	if err != nil {
		t.Fatal(err)
	}
	if got := appSettingsFrom(cfg).KDF; got != cfg.KDF() || got.Memory != 20*1024 {
		t.Errorf("app settings KDF = %+v, want the configured %+v", got, cfg.KDF())
	}
}

// The app's settings name the config file, and whether a change makes it.
func TestUISettings_File(t *testing.T) {
	path := useConfigFile(t, "")
	t.Setenv("HOME", filepath.Dir(filepath.Dir(path))) // said from ~
	for _, made := range []bool{false, true} {
		if made {
			if err := config.Set(path, "history.keep", "7"); err != nil {
				t.Fatal(err)
			}
		}
		cfg, err := settings()
		if err != nil {
			t.Fatal(err)
		}
		for _, s := range uiSettings(cfg) {
			if s.File != "~/sesh/config.toml" || s.NoFile == made {
				t.Errorf("file made %v: %s has File %q, NoFile %v", made, s.Key, s.File, s.NoFile)
			}
		}
	}
}
