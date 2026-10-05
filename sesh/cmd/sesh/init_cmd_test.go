package main

import (
	"bytes"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bashhack/sesh/internal/config"
	"github.com/bashhack/sesh/internal/keychain"
)

// initEnv isolates HOME, the config dir, the data dir, and the agent socket,
// and returns an app whose stdin holds answers, plus the config file path.
func initEnv(t *testing.T, goosValue, answers string) (*App, string) {
	t.Helper()
	path := useConfigFile(t, "")
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_DATA_HOME", filepath.Join(home, ".local", "share"))
	t.Setenv("SESH_AUTH_SOCK", tempAgentSocket(t))
	t.Setenv("SESH_MASTER_PASSWORD", "init-password-1234")
	origGOOS, origOverrides := goos, cliOverrides
	goos, cliOverrides = goosValue, config.Overrides{}
	t.Cleanup(func() { goos, cliOverrides = origGOOS, origOverrides })
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
	app, path := initEnv(t, "darwin", "\n\n")
	if err := runInit(app, nil); err != nil {
		t.Fatal(err)
	}
	got := readFile(t, path)
	if !strings.Contains(got, "key_source = \"password\"\n") || strings.Contains(got, "db_path") || strings.Contains(got, "backend") {
		t.Errorf("config file =\n%s\nwant key_source = password and no db_path (the default)", got)
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

func TestInit_InteractiveKeychainKeyOnMacOS(t *testing.T) {
	kc := newKCMock(nil)
	orig := macKeychain
	macKeychain = func() keychain.ItemStore { return kc }
	t.Cleanup(func() { macKeychain = orig })
	app, path := initEnv(t, "darwin", "2\n\n")
	if err := runInit(app, nil); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, path); !strings.Contains(got, "key_source = \"keychain\"\n") || strings.Contains(got, "backend") {
		t.Errorf("config file =\n%s", got)
	}
	if out := app.Stdout.(*bytes.Buffer).String(); !strings.Contains(out, "kept in your macOS login Keychain") {
		t.Errorf("stdout = %q", out)
	}
	u, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := kc.GetSecret(u.Username, encKeyService); err != nil {
		t.Errorf("the vault's key isn't in the Keychain: %v", err)
	}
	cfg, err := settings()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(cfg.DBPath.Value); err != nil {
		t.Errorf("init didn't create the vault: %v", err)
	}
}

func TestInit_LinuxAsksOnlyForTheLocation(t *testing.T) {
	app, path := initEnv(t, "linux", "~/vaults/sesh.db\n")
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
	app, path := initEnv(t, "darwin", "")
	vault := filepath.Join(t.TempDir(), "flags.db")
	cliOverrides = config.Overrides{DBPath: vault}
	if err := runInit(app, nil); err != nil {
		t.Fatal(err)
	}
	if prompts := app.Stderr.(*bytes.Buffer).String(); strings.Contains(prompts, "Choice [1]") {
		t.Errorf("asked questions despite flags: %q", prompts)
	}
	if got := readFile(t, path); !strings.Contains(got, "db_path = \""+vault+"\"") {
		t.Errorf("config file =\n%s", got)
	}
}

func TestInit_Refuses(t *testing.T) {
	t.Run("existing config without --force", func(t *testing.T) {
		app, path := initEnv(t, "darwin", "\n\n")
		writeTestConfig(t, path, "key_source = \"password\"\n")
		err := runInit(app, nil)
		if err == nil || !strings.Contains(err.Error(), "config already exists") {
			t.Fatalf("err = %v", err)
		}
		if err := runInit(app, []string{"--force"}); err != nil {
			t.Fatalf("--force: %v", err)
		}
	})
	t.Run("keychain on linux", func(t *testing.T) {
		app, path := initEnv(t, "linux", "")
		cliOverrides = config.Overrides{KeySource: "keychain"}
		err := runInit(app, nil)
		if err == nil || !strings.Contains(err.Error(), "isn't available on linux") {
			t.Fatalf("err = %v", err)
		}
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Error("wrote a config file for a refused setup")
		}
	})
	t.Run("a vault in another mode", func(t *testing.T) {
		app, path := initEnv(t, "darwin", "")
		vault := filepath.Join(t.TempDir(), "keychain-key.db")
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
	t.Run("a password vault, choosing the Keychain key", func(t *testing.T) {
		kc := newKCMock(nil)
		orig := macKeychain
		macKeychain = func() keychain.ItemStore { return kc }
		t.Cleanup(func() { macKeychain = orig })
		app, path := initEnv(t, "darwin", "1\n\n")
		if err := runInit(app, nil); err != nil {
			t.Fatal(err)
		}
		app.Stdin = strings.NewReader("2\n\n")
		err := runInit(app, []string{"--force"})
		if err == nil || !strings.Contains(err.Error(), "uses the password key source") {
			t.Fatalf("err = %v, want the vault's own key source named", err)
		}
		u, uerr := user.Current()
		if uerr != nil {
			t.Fatal(uerr)
		}
		if _, gerr := kc.GetSecret(u.Username, encKeyService); gerr == nil {
			t.Error("the refused init left a new key in the Keychain")
		}
		if got := readFile(t, path); !strings.Contains(got, "key_source = \"password\"") {
			t.Errorf("config file =\n%s", got)
		}
	})
	t.Run("an answer that isn't a choice", func(t *testing.T) {
		app, _ := initEnv(t, "darwin", "3\n")
		if err := runInit(app, nil); err == nil || !strings.Contains(err.Error(), "choose 1 or 2") {
			t.Fatalf("err = %v", err)
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

func TestRekey_UpdatesKeySourceInTheConfigFile(t *testing.T) {
	env := setupRekeyEnv(t)
	kc := newKCMock(hexKey())
	populateKeychainStore(t, env, kc, map[string]string{"password/github/alice": "hunter2"})
	path := useConfigFile(t, "# my settings\nkey_source = \"keychain\"  # for now\n\n[agent]\nidle_timeout = \"20m\"\n")
	t.Setenv("SESH_MASTER_PASSWORD", "new-master-password-1234")

	app, stderr := rekeyTestApp("y\n")
	if err := runRekey(app, []string{"--to=password"}, kc); err != nil {
		t.Fatalf("rekey: %v\n%s", err, stderr)
	}
	want := "# my settings\nkey_source = \"password\" # for now\n\n[agent]\nidle_timeout = \"20m\"\n"
	if got := readFile(t, path); got != want {
		t.Errorf("config file =\n%s\nwant\n%s", got, want)
	}
	if !strings.Contains(stderr.String(), `Set key_source = "password" in`) {
		t.Errorf("stderr missing the update note:\n%s", stderr)
	}
}

func TestUpdateKeySourceSetting_EnvAndFlag(t *testing.T) {
	path := useConfigFile(t, "")
	envCfg := &config.Config{Path: path, KeySource: config.Setting[string]{Value: "keychain", Source: config.FromEnv, Origin: "SESH_KEY_SOURCE"}}
	if got := updateKeySourceSetting(envCfg, "password"); !strings.Contains(got, `Change SESH_KEY_SOURCE to "password"`) {
		t.Errorf("env: %q", got)
	}
	flagCfg := &config.Config{Path: path, KeySource: config.Setting[string]{Value: "keychain", Source: config.FromFlag, Origin: "--key-source"}}
	if got := updateKeySourceSetting(flagCfg, "password"); !strings.Contains(got, "Use --key-source password") {
		t.Errorf("flag: %q", got)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("an env or flag setting wrote the config file")
	}
}
