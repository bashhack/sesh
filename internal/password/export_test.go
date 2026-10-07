package password

import (
	"bytes"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/bashhack/sesh/internal/totp"
	"github.com/bashhack/sesh/internal/vault"
)

// An export holds everything about each entry, so restoring it gives the
// same entries: secrets, settings, and times.
func TestExportImport_RoundTripKeepsEverything(t *testing.T) {
	created := time.Date(2025, 4, 5, 6, 7, 8, 0, time.UTC)
	updated := time.Date(2025, 9, 10, 11, 12, 13, 0, time.UTC)
	params := totp.Params{Digits: 8, Algorithm: "SHA256"}
	want := []struct {
		secret string
		entry  vault.Entry
	}{
		{"pw", vault.Entry{Kind: vault.KindPassword, Service: "github", Username: "alice", Folder: "work/dev", Tags: []string{"code", "urgent"}, CreatedAt: created, UpdatedAt: updated}},
		{"JBSWY3DPEHPK3PXP", vault.Entry{Kind: vault.KindTOTP, Service: "bank", Username: "me", Settings: vault.Settings{TOTP: params}, CreatedAt: created, UpdatedAt: updated}},
		{"GEZDGNBVGY3TQOJQ", vault.Entry{Kind: vault.KindTOTP, Service: "aws", Username: "work", Settings: vault.Settings{AWSMFADevice: "arn:aws:iam::1:mfa/me"}, CreatedAt: created, UpdatedAt: updated}},
	}
	for _, format := range []ExportFormat{FormatJSON, FormatCSV} {
		t.Run(string(format), func(t *testing.T) {
			src, srcStore := newTestManager(t)
			for i := range want {
				if err := srcStore.Save(&want[i].entry, []byte(want[i].secret)); err != nil {
					t.Fatal(err)
				}
			}
			var buf bytes.Buffer
			if n, err := src.Export(&buf, ExportOptions{Format: format}); err != nil || n != len(want) {
				t.Fatalf("Export = %d, %v", n, err)
			}

			dst, dstStore := newTestManager(t)
			if res, err := dst.Import(&buf, ImportOptions{Format: format}); err != nil || res.Imported != len(want) || len(res.Errors) != 0 {
				t.Fatalf("Import = %+v, %v", res, err)
			}
			for i := range want {
				w := &want[i]
				got, err := dstStore.Lookup(w.entry.Key)
				if err != nil {
					t.Fatalf("%s: %v", w.entry.Key, err)
				}
				if got.Settings != w.entry.Settings || got.Folder != w.entry.Folder || !slices.Equal(got.Tags, w.entry.Tags) || !got.CreatedAt.Equal(created) || !got.UpdatedAt.Equal(updated) {
					t.Errorf("%s restored as %+v, want %+v", w.entry.Key, got, w.entry)
				}
				if secret, err := dstStore.Get(w.entry.Key); err != nil || string(secret) != w.secret {
					t.Errorf("%s: secret %q, %v; want %q", w.entry.Key, secret, err, w.secret)
				}
			}
			// The restored TOTP entry gives the same codes as the original.
			a, err := src.GenerateTOTPCode("bank", "me")
			if err != nil {
				t.Fatal(err)
			}
			b, err := dst.GenerateTOTPCode("bank", "me")
			if err != nil {
				t.Fatal(err)
			}
			if a != b || len(b) != 8 {
				t.Errorf("codes before and after restoring: %s, %s; want the same 8-digit code", a, b)
			}
		})
	}
}

func TestImport_Conflicts(t *testing.T) {
	m, _ := newTestManager(t)
	if err := m.StorePasswordString("github", "alice", "old", EntryTypePassword); err != nil {
		t.Fatal(err)
	}
	in := `[{"service": "github", "username": "alice", "type": "password", "secret": "new"}]`
	for _, tt := range []struct {
		on              ConflictStrategy
		want            string
		skipped, errors int
	}{
		{"", "old", 0, 1},
		{ConflictSkip, "old", 1, 0},
		{ConflictOverwrite, "new", 0, 0},
	} {
		res, err := m.Import(strings.NewReader(in), ImportOptions{OnConflict: tt.on})
		if err != nil {
			t.Fatal(err)
		}
		got, err := m.GetPasswordString("github", "alice", EntryTypePassword)
		if err != nil || got != tt.want || res.Skipped != tt.skipped || len(res.Errors) != tt.errors {
			t.Errorf("on conflict %q: secret %q (%v), result %+v; want %q, %d skipped, %d errors", tt.on, got, err, res, tt.want, tt.skipped, tt.errors)
		}
	}
}

// Overwriting on import replaces the entry's folder and tags with the
// file's; a bad folder or tag is reported, and the rest still import.
func TestImport_FolderAndTags(t *testing.T) {
	m, store := newTestManager(t)
	k := vault.Key{Kind: vault.KindPassword, Service: "github", Username: "alice"}
	if err := store.Save(&vault.Entry{Key: k, Folder: "old", Tags: []string{"stale"}}, []byte("old")); err != nil {
		t.Fatal(err)
	}
	in := `[{"service": "github", "username": "alice", "type": "password", "secret": "new", "folder": "work", "tags": ["urgent"]},
		{"service": "bad", "type": "password", "secret": "s", "tags": ["a b"]},
		{"service": "ok", "type": "password", "secret": "s"}]`
	res, err := m.Import(strings.NewReader(in), ImportOptions{OnConflict: ConflictOverwrite})
	if err != nil || res.Imported != 2 || len(res.Errors) != 1 || !strings.Contains(res.Errors[0], `"bad": the tag "a b" contains ' '`) {
		t.Fatalf("Import = %+v, %v; want 2 imported and the bad tag reported", res, err)
	}
	if e, err := store.Lookup(k); err != nil || e.Folder != "work" || !slices.Equal(e.Tags, []string{"urgent"}) {
		t.Errorf("overwritten entry = %+v, %v; want folder work, tags [urgent]", e, err)
	}
}

// CSV holds tags joined by ";".
func TestExport_CSVFolderAndTagsColumns(t *testing.T) {
	m, store := newTestManager(t)
	if err := store.Save(&vault.Entry{Kind: vault.KindPassword, Service: "github", Folder: "work", Tags: []string{"b", "a"}}, []byte("pw")); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if _, err := m.Export(&buf, ExportOptions{Format: FormatCSV}); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 || !strings.HasSuffix(lines[0], ",settings,folder,tags") || !strings.HasSuffix(lines[1], ",work,a;b") {
		t.Errorf("CSV = %q, want folder and tags columns holding work and a;b", lines)
	}
}

func TestImport_RejectsBadSettingsInCSV(t *testing.T) {
	m, _ := newTestManager(t)
	in := "service,type,secret,settings\nbank,totp,JBSWY3DPEHPK3PXP,{not json\n"
	if _, err := m.Import(strings.NewReader(in), ImportOptions{Format: FormatCSV}); err == nil || !strings.Contains(err.Error(), "aren't valid JSON") {
		t.Errorf("err = %v, want the bad settings named", err)
	}
}

func TestExport_RejectsUnknownFormat(t *testing.T) {
	mgr, _ := newTestManager(t)
	var buf bytes.Buffer
	_, err := mgr.Export(&buf, ExportOptions{Format: ExportFormat("yaml")})
	if err == nil {
		t.Fatal("expected error for unknown format, got nil")
	}
	if !strings.Contains(err.Error(), "unsupported export format") {
		t.Errorf("error = %v, want contains 'unsupported export format'", err)
	}
}

func TestImport_RejectsUnknownFormat(t *testing.T) {
	mgr, _ := newTestManager(t)
	_, err := mgr.Import(strings.NewReader("{}"), ImportOptions{Format: ExportFormat("xml")})
	if err == nil {
		t.Fatal("expected error for unknown format, got nil")
	}
	if !strings.Contains(err.Error(), "unsupported import format") {
		t.Errorf("error = %v, want contains 'unsupported import format'", err)
	}
}

func TestExport_AcceptsEmptyFormatAsJSON(t *testing.T) {
	// Empty Format is a valid zero value (the default) and should be
	// treated as JSON — matches how callers that omit --format behave.
	mgr, _ := newTestManager(t)
	if err := mgr.StorePasswordString("github", "alice", "pw1", EntryTypePassword); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	count, err := mgr.Export(&buf, ExportOptions{})
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	if count != 1 {
		t.Errorf("count = %d, want 1", count)
	}
	if !strings.HasPrefix(buf.String(), "[") {
		t.Errorf("output should look like a JSON array, got: %q", buf.String())
	}
}

// failingWriter errors once more than budget bytes have been written.
type failingWriter struct {
	budget int
	failed bool
}

func (f *failingWriter) Write(p []byte) (int, error) {
	if f.failed {
		return 0, errors.New("writer closed")
	}
	if len(p) <= f.budget {
		f.budget -= len(p)
		return len(p), nil
	}
	n := f.budget
	f.budget = 0
	f.failed = true
	return n, errors.New("write budget exhausted")
}

func TestExport_StreamsPartialCountOnWriterFailure(t *testing.T) {
	mgr, _ := newTestManager(t)
	const total = 5
	for _, svc := range []string{"a", "b", "c", "d", "e"} {
		if err := mgr.StorePasswordString(svc, "alice", "secret-"+svc, EntryTypePassword); err != nil {
			t.Fatal(err)
		}
	}

	// A buffered-then-write implementation returns count=total regardless
	// of writer success; streaming must return a strictly smaller count
	// when the writer fails mid-way.
	fw := &failingWriter{budget: 200}
	count, err := mgr.Export(fw, ExportOptions{Format: FormatJSON})
	if err == nil {
		t.Fatal("expected error from truncated writer, got nil")
	}
	if count >= total {
		t.Fatalf("non-streaming: got count=%d (want < %d) after write failure", count, total)
	}
}

// An entry whose name no entry can have is reported, and the rest import.
func TestImport_ReportsABadNameAndImportsTheRest(t *testing.T) {
	m, _ := newTestManager(t)
	in := `[{"service": "github ", "type": "password", "secret": "a"},
	        {"service": "gitlab", "type": "password", "secret": "b"}]`
	res, err := m.Import(strings.NewReader(in), ImportOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Imported != 1 || len(res.Errors) != 1 || !strings.HasPrefix(res.Errors[0], `"github ": the service name "github " starts or ends with a space`) {
		t.Errorf("result = %+v, want gitlab imported and github refused for its space", res)
	}
}
