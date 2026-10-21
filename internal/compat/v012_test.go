package compat

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/bashhack/sesh/internal/importer/seshexport"
	"github.com/bashhack/sesh/internal/password"
	"github.com/bashhack/sesh/internal/vault"
)

// What v0.1.2's export was given (testdata/v0.1.2/make.sh): GitHub's
// password with two earlier ones, and a file with an earlier version
// under another name.
const exportPasswordV012 = "fixture-v0.1.2-export"

var (
	kubeNowV012     = "apiVersion: v1\nkind: Config\n"
	kubeEarlierV012 = "apiVersion: v1\nkind: Config\n# old\n"
)

// An encrypted export v0.1.2 wrote, the first to hold earlier secrets, imports into a new vault with them: their
// order, when each was replaced and began, and a file's earlier name.
func TestExportV012(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "v0.1.2", "export.sesh"))
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := password.ReadSealed(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	list, err := sealed.Entries([]byte(exportPasswordV012))
	if err != nil {
		t.Fatal(err)
	}
	st, _ := open(t, filepath.Join(t.TempDir(), "new.db"), "a-new-vault-password")
	st.SetHistoryKeep(10)
	found := map[vault.Key]bool{}
	for _, e := range seshexport.Entries(list) {
		if e.Skip != "" {
			t.Fatalf("%v skipped: %s", e.Key, e.Skip)
		}
		found[e.Key] = true
		for _, h := range e.Earlier {
			if h.ReplacedAt.IsZero() || h.SetAt.IsZero() {
				t.Errorf("%v: an earlier secret without its times: %+v", e.Key, h)
			}
		}
		ent := vault.Entry{Key: e.Key, Folder: e.Folder, Tags: e.Tags, Settings: e.Settings, CreatedAt: e.Created, UpdatedAt: e.Updated}
		if _, err := st.SaveImported(&ent, e.Secret, &e.Details, e.Earlier); err != nil {
			t.Fatalf("%v: %v", e.Key, err)
		}
	}
	if !found[github] || !found[kube] || len(found) != 2 {
		t.Fatalf("entries %v", found)
	}

	for i, want := range append([]string{"gh-pass-3"}, githubEarlier...) {
		var got []byte
		var err error
		if i == 0 {
			got, err = st.Get(github)
		} else {
			got, err = st.ReadVersion(github, i+1, "compat test")
		}
		if err != nil || string(got) != want {
			t.Errorf("GitHub's version %d: %q, %v; want %q", i+1, got, err, want)
		}
	}

	e, err := st.Lookup(kube)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := st.Get(kube); err != nil || string(got) != kubeNowV012 || e.Settings.FileName != "config" {
		t.Errorf("kubeconfig now: %q named %q (%v)", got, e.Settings.FileName, err)
	}
	if _, err := st.RestoreVersion(kube, 2); err != nil {
		t.Fatal(err)
	}
	e, err = st.Lookup(kube)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := st.Get(kube); err != nil || string(got) != kubeEarlierV012 || e.Settings.FileName != "old.yaml" {
		t.Errorf("kubeconfig's earlier version, restored: %q named %q (%v)", got, e.Settings.FileName, err)
	}
}
