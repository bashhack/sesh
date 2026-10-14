package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/bashhack/sesh/internal/config"
)

// healthVault is a vault with weak passwords, one secret on two entries,
// and a strong password, with the master password in the environment.
func healthVault(t *testing.T) {
	t.Helper()
	env := setupRekeyEnv(t)
	useConfigFile(t, "")
	t.Setenv("SESH_MASTER_PASSWORD", "health-password-1234")
	populatePasswordStore(t, env, map[string]string{
		"password/github/alice": "password1",
		"password/gitlab":       "password1",
		"password/bank":         "Wq7#vPz!2kLm9$Xr-Tb4",
		"api_key/openai":        "sk-not-a-real-key-4f8a2c",
	})
}

// The report names the weak and reused entries, and each run is one audit event.
func TestHealth(t *testing.T) {
	healthVault(t)
	out := mustRun(t, runHealth)
	for _, want := range []string{
		"Checked 4 passwords and API keys.",
		"Weak passwords (2): easy to guess\n  password/github/alice\n  password/gitlab\n",
		"Reused (2): the same secret on more than one entry\n  password/github/alice, password/gitlab\n",
		"sesh edit <id> --generate",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "Old (") || strings.Contains(out, "wasn't checked") {
		t.Errorf("entries made today called old, or age said unchecked:\n%s", out)
	}
	out = mustRun(t, runHealth, "--json")
	var r healthJSON
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		t.Fatalf("--json: %v\n%s", err, out)
	}
	if r.Checked != 4 || len(r.Weak) != 2 || len(r.Reused) != 1 || len(r.Old) != 0 || r.Unreadable == nil || r.OldAfterDays != 365 {
		t.Errorf("--json = %+v", r)
	}
	if log := mustRun(t, runAudit); strings.Count(log, "Health check: read 4 secrets") != 2 {
		t.Errorf("each run should be one audit event:\n%s", log)
	}
}

// With no vault, sesh health says so rather than making one.
func TestHealthNoVault(t *testing.T) {
	setupRekeyEnv(t)
	useConfigFile(t, "")
	t.Setenv("SESH_MASTER_PASSWORD", "health-password-1234")
	if _, err := runFiling(t, runHealth); err == nil || !strings.Contains(err.Error(), "there's no vault yet") {
		t.Errorf("with no vault: %v", err)
	}
}

// health.old_after_days 0 turns the age check off, and the report says so.
func TestHealthAgeOff(t *testing.T) {
	healthVault(t)
	t.Setenv(config.EnvHealthOldAfterDays, "0")
	if out := mustRun(t, runHealth); !strings.Contains(out, "Age wasn't checked: health.old_after_days is 0.") {
		t.Errorf("with the age check off:\n%s", out)
	}
}
