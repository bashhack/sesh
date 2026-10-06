package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bashhack/sesh/internal/config"
	"github.com/bashhack/sesh/internal/database"
	"github.com/bashhack/sesh/internal/kdf"
	vaultpkg "github.com/bashhack/sesh/internal/vault"
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
	if _, err := database.ReadUnlockMaterial(cfg.DBPath.Value); err != nil {
		t.Errorf("init didn't create the vault: %v", err)
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
	t.Run("a vault without its key record", func(t *testing.T) {
		app, path := initEnv(t, "")
		vault := filepath.Join(t.TempDir(), "other.db")
		store, err := database.Open(vault, database.NewKeySourceOracle(&recoveredKey{key: bytes.Repeat([]byte{1}, 32)}))
		if err != nil {
			t.Fatal(err)
		}
		if err := store.Put(vaultpkg.Key{Kind: vaultpkg.KindPassword, Service: "github"}, []byte("hunter2")); err != nil {
			t.Fatal(err)
		}
		closeAuditStore(store)
		cliOverrides = config.Overrides{DBPath: vault}
		err = runInit(app, nil)
		if err == nil || !strings.Contains(err.Error(), "holds entries but not the record its key is made from") {
			t.Fatalf("err = %v, want the missing key record refusal", err)
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

// sesh init creates the vault with the Argon2id settings sesh config will
// show afterwards: the environment's, or the defaults, and never an old
// config file's, which init replaces. A bad setting stops it.
func TestInit_KDFSettings(t *testing.T) {
	t.Run("from the environment", func(t *testing.T) {
		app, _ := initEnv(t, "\n")
		t.Setenv("SESH_KDF_MEMORY", "20MiB")
		if err := runInit(app, nil); err != nil {
			t.Fatal(err)
		}
		wantKDF(t, kdf.Params{Time: 2, Memory: 20 * 1024, Threads: 1, KeyLen: kdf.KeyLen})
	})
	t.Run("not an old file's", func(t *testing.T) {
		app, path := initEnv(t, "\n")
		writeTestConfig(t, path, "[master_password]\nmemory = \"21MiB\"\n")
		t.Setenv("SESH_KDF_MEMORY", "")
		if err := runInit(app, []string{"--force"}); err != nil {
			t.Fatal(err)
		}
		wantKDF(t, kdf.Params{Time: 2, Memory: kdf.DefaultMemoryKiB, Threads: 1, KeyLen: kdf.KeyLen})
	})
	t.Run("a bad setting", func(t *testing.T) {
		app, path := initEnv(t, "\n")
		t.Setenv("SESH_KDF_MEMORY", "512MB")
		err := runInit(app, nil)
		if err == nil || !strings.Contains(err.Error(), `SESH_KDF_MEMORY = "512MB"`) {
			t.Fatalf("err = %v, want the bad setting named", err)
		}
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Error("wrote a config file")
		}
	})
}

// wantKDF fails unless the vault sesh config names has key record settings
// want, and sesh config shows them.
func wantKDF(t *testing.T, want kdf.Params) {
	t.Helper()
	cfg, err := settings()
	if err != nil {
		t.Fatal(err)
	}
	m, err := database.ReadUnlockMaterial(cfg.DBPath.Value)
	if err != nil {
		t.Fatal(err)
	}
	if m.Params != want || cfg.KDF() != want {
		t.Errorf("vault settings = %+v, sesh config shows %+v; want %+v", m.Params, cfg.KDF(), want)
	}
}
