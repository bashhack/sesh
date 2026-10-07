package setup

import (
	"bufio"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/bashhack/sesh/internal/qrcode"
	"github.com/bashhack/sesh/internal/testutil"
	"github.com/bashhack/sesh/internal/vault"
)

// runTOTPSetup runs the TOTP wizard on store with input and filing,
// returning what it printed.
func runTOTPSetup(t *testing.T, store vault.Store, input string, filing vault.Filing) string {
	t.Helper()
	stubTOTPSetup(t, qrcode.TOTPInfo{}, "JBSWY3DPEHPK3PXP")
	handler := &TOTPSetupHandler{store: store, reader: bufio.NewReader(strings.NewReader(input))}
	var err error
	out := testutil.CaptureStdout(func() { err = handler.Setup(filing) })
	if err != nil {
		t.Fatalf("Setup(): %v\n%s", err, out)
	}
	return out
}

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

// --folder or --tag file the entry, and the wizard doesn't ask.
func TestTOTPSetup_FilesFromFlags(t *testing.T) {
	store := vault.NewMemStore()
	out := runTOTPSetup(t, store, "svc\n\n1\n", vault.Filing{Folder: "work", FolderSet: true, Tags: []string{"a"}})
	if strings.Contains(out, "Folder (") || strings.Contains(out, "Tags (") {
		t.Errorf("the wizard asked although the flags said:\n%s", out)
	}
	checkFiled(t, store, vault.Key{Kind: vault.KindTOTP, Service: "svc"}, "work", "a")
}

// Without the flags the wizard asks, and asks again after an answer no
// folder or tag can have.
func TestTOTPSetup_AsksWhereToFile(t *testing.T) {
	store := vault.NewMemStore()
	out := runTOTPSetup(t, store, "svc\n\n1\nwork//x\nwork/dev\na b,c\na b\n", vault.Filing{})
	for _, want := range []string{"Folder (optional, such as work/aws; Enter for none): ", `the folder "work//x" has an empty part`, `the tag "b,c" contains ','`} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
	checkFiled(t, store, vault.Key{Kind: vault.KindTOTP, Service: "svc"}, "work/dev", "a", "b")
}

// Replacing an entry, Enter keeps its folder, and tags are added to its own.
func TestTOTPSetup_ReplacingKeepsTheFiling(t *testing.T) {
	store := vault.NewMemStore()
	k := vault.Key{Kind: vault.KindTOTP, Service: "svc"}
	if err := store.Save(&vault.Entry{Key: k, Folder: "old", Tags: []string{"x"}}, []byte("OLDSECRETOLDSECR")); err != nil {
		t.Fatal(err)
	}
	out := runTOTPSetup(t, store, "svc\n\ny\n1\n\ny\n", vault.Filing{})
	for _, want := range []string{"Folder (Enter keeps old): ", "Tags to add (it has x; Enter adds none): "} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
	checkFiled(t, store, k, "old", "x", "y")
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
