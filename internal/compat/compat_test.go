// Package compat holds files written by released versions of sesh, and
// tests that this one still reads them: a vault, an encrypted export and a
// sync folder, each with made-up entries. A change to how any of them is
// stored needs a way to read what a release wrote; these tests fail
// without one.
package compat

import (
	"bytes"
	"database/sql"
	"os"
	"path/filepath"
	"slices"
	"testing"

	_ "modernc.org/sqlite"

	"github.com/bashhack/sesh/internal/database"
	"github.com/bashhack/sesh/internal/importer/seshexport"
	"github.com/bashhack/sesh/internal/password"
	"github.com/bashhack/sesh/internal/syncfolder"
	"github.com/bashhack/sesh/internal/totp"
	"github.com/bashhack/sesh/internal/vault"
	"github.com/bashhack/sesh/internal/vaultsync"
)

// The made-up passwords v0.1.1's files were written with.
const (
	masterPassword = "fixture-v0.1.1-master"
	exportPassword = "fixture-v0.1.1-export"
)

// What v0.1.1's vault was given (make.sh), entry by entry.
var (
	github     = vault.Key{Kind: vault.KindPassword, Service: "GitHub", Username: "maya"}
	githubTOTP = vault.Key{Kind: vault.KindTOTP, Service: "GitHub", Username: "maya"}
	openai     = vault.Key{Kind: vault.KindAPIKey, Service: "OpenAI"}
	house      = vault.Key{Kind: vault.KindNote, Service: "House"}
	kube       = vault.Key{Kind: vault.KindFile, Service: "kubeconfig"}
	shop       = vault.Key{Kind: vault.KindPassword, Service: "Shop", Username: "maya@example.org"}

	// Each entry's secret.
	secrets = map[vault.Key]string{
		github:     "gh-pass-3",
		githubTOTP: "JBSWY3DPEHPK3PXP",
		openai:     "sk-test-0123456789abcdef",
		house:      "Door code 4711\nAlarm 2580\n",
		kube:       "apiVersion: v1\nkind: Config\n",
	}
	// Each entry's settings: the TOTP's code settings decide which codes
	// are right.
	settings = map[vault.Key]vault.Settings{
		githubTOTP: {TOTP: totp.Params{Issuer: "GitHub", Algorithm: "SHA256", Digits: 8, Period: 60}},
		kube:       {FileName: "kubeconfig"},
	}
	// GitHub's earlier secrets, the newest first.
	githubEarlier = []string{"gh-pass-2", "gh-pass-1"}
)

// copied is the release's file or folder at name, copied to a temporary
// folder, so a test's writes never reach the one kept here.
func copied(t *testing.T, release, name string) string { //nolint:unparam // a release that changes a format adds files of its own
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

// open opens the vault at path with password, making it when there's none,
// and returns its key too.
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

// checkVault fails for each entry whose secret, settings or filing isn't
// what v0.1.1 kept, and for GitHub's details.
func checkVault(t *testing.T, st *database.Store) {
	t.Helper()
	for k, want := range secrets {
		got, err := st.Get(k)
		if err != nil || string(got) != want {
			t.Errorf("%v: %q, %v; want %q", k, got, err, want)
		}
		e, err := st.Lookup(k)
		if err != nil {
			t.Errorf("%v: %v", k, err)
			continue
		}
		if e.Settings != settings[k] {
			t.Errorf("%v's settings: %+v, want %+v", k, e.Settings, settings[k])
		}
		if k == github && (e.Folder != "work" || !slices.Equal(e.Tags, []string{"dev"})) {
			t.Errorf("GitHub filed in %q, tagged %q", e.Folder, e.Tags)
		}
	}
	d, err := st.Details(github, "compat test")
	if err != nil {
		t.Fatal(err)
	}
	checkGitHubDetails(t, &d)
}

// checkGitHubDetails fails unless d is GitHub's URL, notes and fields.
func checkGitHubDetails(t *testing.T, d *vault.Details) {
	t.Helper()
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
	if len(fields) != 2 || fields["recovery-email"] != "maya@example.com" || fields["pin"] != "4711" {
		t.Errorf("GitHub's fields %v", fields)
	}
}

// A vault v0.1.1 made opens, and every entry, its details, its earlier secrets and the trash read back.
func TestVaultV011(t *testing.T) {
	st, _ := open(t, copied(t, "v0.1.1", "vault.db"), masterPassword)
	checkVault(t, st)

	entries, err := st.List(&vault.Filter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != len(secrets) {
		t.Errorf("%d entries, want the %d v0.1.1 kept", len(entries), len(secrets))
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

// schema is the tables, indexes and triggers of the vault at path, as
// SQLite holds their definitions.
func schema(t *testing.T, path string) []string {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := db.Close(); err != nil {
			t.Error(err)
		}
	}()
	rows, err := db.Query(`SELECT type || ' ' || name || ': ' || COALESCE(sql, '') FROM sqlite_master ORDER BY type, name`)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			t.Fatal(err)
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// v0.1.1's vault, opened (and so upgraded), is laid out as a new vault is: a change to an upgrade step already
// released, rather than a new step, leaves the two apart.
func TestVaultSchemaV011(t *testing.T) {
	old := copied(t, "v0.1.1", "vault.db")
	open(t, old, masterPassword)
	fresh := filepath.Join(t.TempDir(), "new.db")
	open(t, fresh, "a-new-vault-password")
	a, b := schema(t, old), schema(t, fresh)
	for _, s := range a {
		if !slices.Contains(b, s) {
			t.Errorf("only in the upgraded v0.1.1 vault: %s", s)
		}
	}
	for _, s := range b {
		if !slices.Contains(a, s) {
			t.Errorf("only in a new vault: %s", s)
		}
	}
}

// An encrypted export v0.1.1 wrote reads, as sesh import reads it: every entry with its secret, settings, filing and
// details (its exports carry no earlier secrets).
func TestExportV011(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "v0.1.1", "export.sesh"))
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := password.ReadSealed(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	list, err := sealed.Entries([]byte(exportPassword))
	if err != nil {
		t.Fatal(err)
	}
	got := map[vault.Key]bool{}
	for _, e := range seshexport.Entries(list) {
		got[e.Key] = true
		if e.Skip != "" {
			t.Errorf("%v skipped: %s", e.Key, e.Skip)
			continue
		}
		if string(e.Secret) != secrets[e.Key] || e.Settings != settings[e.Key] {
			t.Errorf("%v: secret %q, settings %+v", e.Key, e.Secret, e.Settings)
		}
		if len(e.Earlier) != 0 {
			t.Errorf("%v: %d earlier secrets, from an export that has none", e.Key, len(e.Earlier))
		}
		if e.Key == github {
			if e.Folder != "work" || !slices.Equal(e.Tags, []string{"dev"}) {
				t.Errorf("GitHub filed in %q, tagged %q", e.Folder, e.Tags)
			}
			checkGitHubDetails(t, &e.Details)
		}
	}
	for k := range secrets {
		if !got[k] {
			t.Errorf("%v isn't in the export", k)
		}
	}
}

// A sync folder v0.1.1 made reads: every entry's file opens with the vault's key, with its secret, settings and
// earlier secrets, and the trashed entry marked so.
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
	if len(c.Problems) != 0 {
		t.Errorf("problems: %v", c.Problems)
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
		r := got[k]
		if r == nil || string(r.Secret) != want || r.Settings != settings[k] {
			t.Errorf("%v: %+v, want secret %q, settings %+v", k, r, want, settings[k])
		}
	}
	if r := got[github]; r == nil || len(r.History) != len(githubEarlier) || r.URL != "https://github.com/login" {
		t.Errorf("GitHub in the folder: %+v", r)
	}
	if r := got[shop]; r == nil || r.Deleted.IsZero() {
		t.Errorf("Shop, in the trash, isn't marked so in the folder: %+v", r)
	}
}

// v0.1.1's vault syncs with its own folder and finds nothing to do: what it kept of the folder still reads.
func TestSyncV011(t *testing.T) {
	st, _ := open(t, copied(t, "v0.1.1", "vault.db"), masterPassword)
	sum, err := vaultsync.SyncWith(st, syncfolder.New(copied(t, "v0.1.1", "sync")), "test-laptop", vaultsync.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(sum.Received)+len(sum.Sent)+len(sum.Merged)+len(sum.Problems)+len(sum.Warnings) != 0 {
		t.Errorf("syncing v0.1.1's vault with its own folder did something: %+v", *sum)
	}
}

// Another computer joins v0.1.1's sync folder with its master password, and gets every entry.
func TestJoinV011(t *testing.T) {
	f := syncfolder.New(copied(t, "v0.1.1", "sync"))
	info, err := f.ReadInfo()
	if err != nil {
		t.Fatal(err)
	}
	m := database.UnlockMaterial{Salt: info.Key.Salt, Verify: info.Key.Verify, Params: info.Key.Params}
	if err := database.CheckMasterPassword([]byte(masterPassword), m); err != nil {
		t.Fatalf("the folder's key record: %v", err)
	}
	p := filepath.Join(t.TempDir(), "joined.db")
	if _, err := database.JoinVault(p, m, info.FolderID, info.Links); err != nil {
		t.Fatal(err)
	}
	st, _ := open(t, p, masterPassword)
	if _, err := vaultsync.SyncWith(st, f, "other-laptop", vaultsync.Options{}); err != nil {
		t.Fatal(err)
	}
	checkVault(t, st)
}
