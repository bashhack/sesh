package main

import (
	"crypto/sha1" //nolint:gosec // the Pwned Passwords download's keys
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
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

// breachFile is a one-file Pwned Passwords download holding the words, each seen count times, among others.
func breachFile(t *testing.T, count string, words ...string) string {
	t.Helper()
	lines := []string{"0000000000000000000000000000000000000001:7", "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:3"}
	for _, w := range words {
		sum := sha1.Sum([]byte(w)) //nolint:gosec // the download's keys
		lines = append(lines, strings.ToUpper(hex.EncodeToString(sum[:]))+":"+count)
	}
	slices.Sort(lines)
	path := filepath.Join(t.TempDir(), "pwnedpasswords.txt")
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// The report names the weak, reused and breached entries, and says what it didn't check.
func TestHealth(t *testing.T) {
	healthVault(t)
	out := mustRun(t, runHealth)
	for _, want := range []string{
		"Checked 4 passwords and API keys.",
		"Weak passwords (2): easy to guess\n  password/github/alice\n  password/gitlab\n",
		"Reused (2): the same secret on more than one entry\n  password/github/alice, password/gitlab\n",
		"sesh edit <id> --generate",
		"Breaches weren't checked. To check them",
		"haveibeenpwned-downloader pwnedpasswords --single",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "Old (") {
		t.Errorf("entries made today called old:\n%s", out)
	}
	// A relative path, as typed in a terminal.
	file := breachFile(t, "2384", "password1")
	t.Chdir(filepath.Dir(file))
	out = mustRun(t, runHealth, "--hibp", filepath.Base(file), "--json")
	var r healthJSON
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		t.Fatalf("--json: %v\n%s", err, out)
	}
	if !r.BreachesChecked || len(r.Breached) != 2 || r.Breached[0].ID != "password/github/alice" || r.Breached[0].Count != 2384 || r.Checked != 4 || len(r.Old) != 0 {
		t.Errorf("--json = %+v", r)
	}
	if log := mustRun(t, runAudit); strings.Count(log, "Health check: read 4 secrets") != 2 {
		t.Errorf("each run should be one audit event:\n%s", log)
	}
}

// health.hibp_file is used when --hibp isn't given; a download that's wrong is said before the vault is unlocked.
func TestHealthBreachSettings(t *testing.T) {
	healthVault(t)
	t.Setenv(config.EnvHealthHIBPFile, breachFile(t, "1", "Wq7#vPz!2kLm9$Xr-Tb4"))
	if out := mustRun(t, runHealth); !strings.Contains(out, "Breached (1): seen in data breaches") || !strings.Contains(out, "password/bank") {
		t.Errorf("with health.hibp_file:\n%s", out)
	}
	ntlm := filepath.Join(t.TempDir(), "ntlm.txt")
	if err := os.WriteFile(ntlm, []byte("00000011059407D743D40689940F858C:3\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SESH_MASTER_PASSWORD", "not-the-password")
	if _, err := runFiling(t, runHealth, "--hibp", ntlm); err == nil || !strings.Contains(err.Error(), "NTLM download") {
		t.Errorf("the NTLM download: %v", err)
	}
}
