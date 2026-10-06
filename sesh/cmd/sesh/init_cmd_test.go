package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bashhack/sesh/internal/config"
)

// initEnv isolates HOME, the config dir, the data dir, and the agent socket,
// and returns an app whose stdin holds answers, plus the config file path.
func initEnv(t *testing.T, answers string) (*App, string) {
	t.Helper()
	path := useConfigFile(t, "")
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_DATA_HOME", filepath.Join(home, ".local", "share"))
	t.Setenv("SESH_AUTH_SOCK", tempAgentSocket(t))
	t.Setenv("SESH_MASTER_PASSWORD", "init-password-1234")
	origOverrides := cliOverrides
	cliOverrides = config.Overrides{}
	t.Cleanup(func() { cliOverrides = origOverrides })
	app := agentTestApp()
	app.Stdin = strings.NewReader(answers)
	return app, path
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestInit_InteractiveDefaults(t *testing.T) {
	app, path := initEnv(t, "\n")
	if err := runInit(app, nil); err != nil {
		t.Fatal(err)
	}
	got := readFile(t, path)
	if strings.Contains(got, "db_path") || strings.Contains(got, "key_source") || strings.Contains(got, "backend") {
		t.Errorf("config file =\n%s\nwant no settings (all defaults)", got)
	}
	cfg, err := settings()
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{cfg.DBPath.Value, filepath.Join(filepath.Dir(cfg.DBPath.Value), sidecarFile)} {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("init didn't create %s: %v", p, err)
		}
	}
	if out := app.Stdout.(*bytes.Buffer).String(); !strings.Contains(out, "Ready. Run `sesh config`") {
		t.Errorf("stdout = %q", out)
	}
}

func TestInit_AsksOnlyForTheLocation(t *testing.T) {
	app, path := initEnv(t, "~/vaults/sesh.db\n")
	if err := runInit(app, nil); err != nil {
		t.Fatal(err)
	}
	if prompts := app.Stderr.(*bytes.Buffer).String(); strings.Contains(prompts, "macOS Keychain") || !strings.Contains(prompts, "Vault location [") {
		t.Errorf("prompts = %q, want only the vault location", prompts)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	vault := filepath.Join(home, "vaults", "sesh.db")
	if got := readFile(t, path); !strings.Contains(got, "db_path = \"~/vaults/sesh.db\"") {
		t.Errorf("config file =\n%s", got)
	}
	if _, err := os.Stat(vault); err != nil {
		t.Errorf("vault not created: %v", err)
	}
}

func TestInit_FromFlags(t *testing.T) {
	app, path := initEnv(t, "")
	vault := filepath.Join(t.TempDir(), "flags.db")
	cliOverrides = config.Overrides{DBPath: vault}
	if err := runInit(app, nil); err != nil {
		t.Fatal(err)
	}
	if prompts := app.Stderr.(*bytes.Buffer).String(); strings.Contains(prompts, "Vault location") {
		t.Errorf("asked questions despite flags: %q", prompts)
	}
	if got := readFile(t, path); !strings.Contains(got, "db_path = \""+vault+"\"") {
		t.Errorf("config file =\n%s", got)
	}
}

func TestInit_Refuses(t *testing.T) {
	t.Run("existing config without --force", func(t *testing.T) {
		app, path := initEnv(t, "\n")
		writeTestConfig(t, path, "clipboard_timeout = \"45s\"\n")
		err := runInit(app, nil)
		if err == nil || !strings.Contains(err.Error(), "config already exists") {
			t.Fatalf("err = %v", err)
		}
		if err := runInit(app, []string{"--force"}); err != nil {
			t.Fatalf("--force: %v", err)
		}
	})
	t.Run("a vault without its key file", func(t *testing.T) {
		app, path := initEnv(t, "")
		vault := filepath.Join(t.TempDir(), "other.db")
		if err := os.WriteFile(vault, []byte("not empty"), 0o600); err != nil {
			t.Fatal(err)
		}
		cliOverrides = config.Overrides{DBPath: vault}
		err := runInit(app, nil)
		if err == nil || !strings.Contains(err.Error(), "its key file") {
			t.Fatalf("err = %v, want the missing passwords.key refusal", err)
		}
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Error("wrote a config file for a refused setup")
		}
	})
}

func writeTestConfig(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}
