package setup

import (
	"bufio"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/bashhack/sesh/internal/testutil"
	"github.com/bashhack/sesh/internal/vault"
)

func checkFiled(t *testing.T, store vault.Store, k vault.Key, folder string, tags ...string) vault.Entry {
	t.Helper()
	e, err := store.Lookup(k)
	if err != nil {
		t.Fatal(err)
	}
	if e.Folder != folder || !slices.Equal(e.Tags, tags) {
		t.Errorf("filed in %q with tags %q; want %q, %q", e.Folder, e.Tags, folder, tags)
	}
	return e
}

// Setting AWS up again keeps the entry's folder, tags, and creation time,
// and the flags work there too.
func TestAWSSetup_ReplacingKeepsTheFiling(t *testing.T) {
	const device = "arn:aws:iam::123456789012:mfa/testuser"
	stubAWSSetup(t, device)
	store := vault.NewMemStore()
	k := vault.AWSKey("")
	created := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	if err := store.Save(&vault.Entry{Key: k, Folder: "work", Tags: []string{"x"}, CreatedAt: created, Settings: vault.Settings{AWSMFADevice: "old"}}, []byte("OLDSECRETOLDSECR")); err != nil {
		t.Fatal(err)
	}
	// profile, overwrite, manual entry, Enter after the console codes,
	// first device; no folder or tag questions, since --tag says.
	handler := &AWSSetupHandler{store: store, reader: bufio.NewReader(strings.NewReader("\ny\n1\n\n1\n"))}
	var err error
	out := testutil.CaptureStdout(func() { err = handler.Setup(vault.Filing{Tags: []string{"y"}}) })
	if err != nil {
		t.Fatalf("Setup(): %v\n%s", err, out)
	}
	e := checkFiled(t, store, k, "work", "x", "y")
	if !e.CreatedAt.Equal(created) || e.Settings.AWSMFADevice != device {
		t.Errorf("entry = %+v; want the creation time kept and the new device", e)
	}
}

// The AWS wizard asks where to file the entry too.
func TestAWSSetup_AsksWhereToFile(t *testing.T) {
	stubAWSSetup(t, "arn:aws:iam::123456789012:mfa/testuser")
	store := vault.NewMemStore()
	handler := &AWSSetupHandler{store: store, reader: bufio.NewReader(strings.NewReader("\n1\n\n1\nwork/aws\nprod mfa\n"))}
	var err error
	out := testutil.CaptureStdout(func() { err = handler.Setup(vault.Filing{}) })
	if err != nil {
		t.Fatalf("Setup(): %v\n%s", err, out)
	}
	checkFiled(t, store, vault.AWSKey(""), "work/aws", "mfa", "prod")
}
