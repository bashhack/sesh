// Package compat holds files written by released versions of sesh, and
// tests that this one still reads them: a vault, an encrypted export and a
// sync folder, each with made-up entries. A change to how any of them is
// stored needs a way to read what a release wrote; these tests fail
// without one.
package compat

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/bashhack/sesh/internal/database"
	"github.com/bashhack/sesh/internal/password"
	"github.com/bashhack/sesh/internal/syncfolder"
	"github.com/bashhack/sesh/internal/vault"
)

// The made-up passwords v0.1.1's files were written with.
const (
	masterPassword = "fixture-v0.1.1-master"
	exportPassword = "fixture-v0.1.1-export"
)

// What v0.1.1's vault was given, entry by entry: each kept secret, and for
// the GitHub login, its earlier ones, newest first.
var (
	github     = vault.Key{Kind: vault.KindPassword, Service: "GitHub", Username: "maya"}
	githubTOTP = vault.Key{Kind: vault.KindTOTP, Service: "GitHub", Username: "maya"}
	openai     = vault.Key{Kind: vault.KindAPIKey, Service: "OpenAI"}
	house      = vault.Key{Kind: vault.KindNote, Service: "House"}
	kube       = vault.Key{Kind: vault.KindFile, Service: "kubeconfig"}
	shop       = vault.Key{Kind: vault.KindPassword, Service: "Shop", Username: "maya@example.org"}
	secrets    = map[vault.Key]string{
		github:     "gh-pass-3",
		githubTOTP: "JBSWY3DPEHPK3PXP",
		openai:     "sk-test-0123456789abcdef",
		house:      "Door code 4711\nAlarm 2580\n",
		kube:       "apiVersion: v1\nkind: Config\n",
	}
	githubEarlier = []string{"gh-pass-2", "gh-pass-1"}
)

// copied is the release's file or folder at name, copied to a temporary
// folder, so a test's writes never reach the one kept here.
func copied(t *testing.T, release, name string) string {
	t.Helper()
	src := filepath.Join("testdata", release, name)
	dst := filepath.Join(t.TempDir(), name)
	err := filepath.WalkDir(src, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, p)
		if err != nil {
			return err
		}
		to := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(to, 0o700)
		}
		b, err := os.ReadFile(p) //nolint:gosec // the test's own files
		if err != nil {
			return err
		}
		return os.WriteFile(to, b, 0o600)
	})
	if err != nil {
		t.Fatal(err)
	}
	return dst
}

// open opens the vault at path with password, and returns its key too.
func open(t *testing.T, path, pw string) (*database.Store, []byte) {
	t.Helper()
	src := database.NewMasterPasswordSource(path, func(string) ([]byte, error) { return []byte(pw), nil })
	st, err := database.Open(path, database.NewKeySourceOracle(src))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() {
		if err := st.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	key, err := src.GetEncryptionKey()
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	return st, key
}

// checkSecrets fails for each entry whose secret isn't the one v0.1.1 kept.
func checkSecrets(t *testing.T, st *database.Store) {
	t.Helper()
	for k, want := range secrets {
		got, err := st.Get(k)
		if err != nil || string(got) != want {
			t.Errorf("%v: %q, %v; want %q", k, got, err, want)
		}
	}
}

// A vault v0.1.1 made opens, and every entry, its details, its earlier secrets and the trash read back.
func TestVaultV011(t *testing.T) {
	st, _ := open(t, copied(t, "v0.1.1", "vault.db"), masterPassword)
	checkSecrets(t, st)

	entries, err := st.List(&vault.Filter{})
	if err != nil {
		t.Fatal(err)
	}
	var keys []vault.Key
	for _, e := range entries {
		keys = append(keys, e.Key)
		if e.Key == github && (e.Folder != "work" || !slices.Equal(e.Tags, []string{"dev"})) {
			t.Errorf("GitHub filed in %q, tagged %q", e.Folder, e.Tags)
		}
	}
	if len(keys) != len(secrets) {
		t.Errorf("entries %v, want the %d v0.1.1 kept", keys, len(secrets))
	}

	d, err := st.Details(github, "compat test")
	if err != nil {
		t.Fatal(err)
	}
	if d.URL != "https://github.com/login" || string(d.Notes) != "Personal account. Recovery codes in the safe.\n" {
		t.Errorf("GitHub's URL %q, notes %q", d.URL, d.Notes)
	}
	fields := map[string]string{}
	for _, f := range d.Fields {
		fields[f.Name] = string(f.Value)
		if f.Secret != (f.Name == "pin") {
			t.Errorf("field %s secret=%v", f.Name, f.Secret)
		}
	}
	if fields["recovery-email"] != "maya@example.com" || fields["pin"] != "4711" {
		t.Errorf("GitHub's fields %v", fields)
	}

	for i, want := range githubEarlier {
		got, err := st.ReadVersion(github, i+2, "compat test") // version 1 is the secret now
		if err != nil || string(got) != want {
			t.Errorf("GitHub's version %d: %q, %v; want %q", i+2, got, err, want)
		}
	}

	trash, err := st.Trash()
	if err != nil {
		t.Fatal(err)
	}
	if len(trash) != 1 || trash[0].Key != shop {
		t.Errorf("trash %v, want Shop", trash)
	}
}

// An encrypted export v0.1.1 wrote imports into a new vault, every entry with it (its exports carry no earlier secrets).
func TestExportV011(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "v0.1.1", "export.sesh"))
	if err != nil {
		t.Fatal(err)
	}
	st, _ := open(t, filepath.Join(t.TempDir(), "new.db"), "a-new-vault-password")
	m := password.NewManager(st)
	if _, err := m.ImportEncrypted(bytes.NewReader(data), password.ImportOptions{}, []byte(exportPassword)); err != nil {
		t.Fatalf("import: %v", err)
	}
	checkSecrets(t, st)
}

// A sync folder v0.1.1 made reads, every entry's file opening with the vault's key.
func TestSyncFolderV011(t *testing.T) {
	_, key := open(t, copied(t, "v0.1.1", "vault.db"), masterPassword)
	f := syncfolder.New(copied(t, "v0.1.1", "sync"))
	if _, err := f.ReadInfo(); err != nil {
		t.Fatalf("sesh-sync.json: %v", err)
	}
	c, err := f.Scan()
	if err != nil {
		t.Fatal(err)
	}
	got := map[vault.Key]*syncfolder.Record{}
	for i := range c.Files {
		b, err := f.Read(&c.Files[i])
		if err != nil {
			t.Fatal(err)
		}
		_, rec, err := syncfolder.Open(database.KeySealer(key), b)
		if err != nil {
			t.Fatalf("%s: %v", c.Files[i].Path, err)
		}
		got[vault.Key{Kind: rec.Kind, Service: rec.Service, Username: rec.Username}] = rec
	}
	for k, want := range secrets {
		if r := got[k]; r == nil || string(r.Secret) != want {
			t.Errorf("%v: %+v, want secret %q", k, r, want)
		}
	}
	if r := got[github]; r == nil || len(r.History) != len(githubEarlier) {
		t.Errorf("GitHub's earlier secrets in the folder: %+v", r)
	}
	if r := got[shop]; r == nil || r.Deleted.IsZero() {
		t.Errorf("Shop, in the trash, isn't marked so in the folder: %+v", r)
	}
	if len(c.Problems) != 0 {
		t.Errorf("problems: %v", c.Problems)
	}
}
