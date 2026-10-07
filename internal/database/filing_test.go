package database

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/bashhack/sesh/internal/vault"
)

// filedStore is a vault holding entries a–e in folders and with tags.
func filedStore(t *testing.T) *Store {
	t.Helper()
	p := vaultPath(t.TempDir())
	s, err := Open(p, NewKeySourceOracle(NewMasterPasswordSource(p, staticPrompt("filing-password-1", "filing-password-1"))))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() }) //nolint:errcheck // test cleanup
	if err := s.CheckKey(); err != nil {
		t.Fatal(err)
	}
	old := time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC)
	for _, e := range []*vault.Entry{
		{Kind: vault.KindPassword, Service: "a", Folder: "work", Tags: []string{"x"}},
		{Kind: vault.KindPassword, Service: "b", Folder: "work/dev", Tags: []string{"x", "y"}},
		{Kind: vault.KindPassword, Service: "c", Folder: "workshop"},
		{Kind: vault.KindPassword, Service: "d", Folder: "job"},
		{Kind: vault.KindPassword, Service: "e"},
	} {
		e.CreatedAt, e.UpdatedAt = old, old
		if err := s.Save(e, []byte("s")); err != nil {
			t.Fatal(err)
		}
	}
	return s
}

func pw(service string) vault.Key { return vault.Key{Kind: vault.KindPassword, Service: service} }

// filed is "service:folder:tag,tag" for every entry, in order.
func filed(t *testing.T, s *Store) string {
	t.Helper()
	all, err := s.List(&vault.Filter{})
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for i := range all {
		out = append(out, all[i].Service+":"+all[i].Folder+":"+strings.Join(all[i].Tags, ","))
	}
	return strings.Join(out, " ")
}

const start = "a:work:x b:work/dev:x,y c:workshop: d:job: e::"

func TestMoveToFolder(t *testing.T) {
	s := filedStore(t)
	n, err := s.MoveToFolder([]vault.Key{pw("a"), pw("e"), pw("d")}, "job")
	if err != nil || n != 2 {
		t.Fatalf("MoveToFolder = %d, %v; want 2 (d was already there)", n, err)
	}
	if got := filed(t, s); got != "a:job:x b:work/dev:x,y c:workshop: d:job: e:job:" {
		t.Errorf("after the move: %s", got)
	}
	// Out of any folder.
	if n, err := s.MoveToFolder([]vault.Key{pw("e")}, ""); err != nil || n != 1 {
		t.Errorf("out of its folder: %d, %v", n, err)
	}
	// A move isn't an update to the entry: its update time stays.
	if e, err := s.Lookup(pw("a")); err != nil || e.UpdatedAt.Year() != 2025 {
		t.Errorf("a = %+v, %v; want its update time kept", e, err)
	}
}

func TestFilingChanges_AllOrNone(t *testing.T) {
	s := filedStore(t)
	missing := pw("missing")
	if _, err := s.MoveToFolder([]vault.Key{pw("e"), missing}, "job"); !errors.Is(err, vault.ErrNotFound) {
		t.Errorf("MoveToFolder with a missing entry = %v, want ErrNotFound", err)
	}
	if _, err := s.AddTag([]vault.Key{pw("e"), missing}, "z"); !errors.Is(err, vault.ErrNotFound) {
		t.Errorf("AddTag with a missing entry = %v, want ErrNotFound", err)
	}
	if _, err := s.RemoveTag([]vault.Key{pw("a"), missing}, "x"); !errors.Is(err, vault.ErrNotFound) {
		t.Errorf("RemoveTag with a missing entry = %v, want ErrNotFound", err)
	}
	if _, err := s.MoveToFolder([]vault.Key{pw("e")}, "/bad"); err == nil {
		t.Error("MoveToFolder to a bad folder succeeded")
	}
	if _, err := s.AddTag([]vault.Key{pw("e")}, "a b"); err == nil {
		t.Error("AddTag of a bad tag succeeded")
	}
	if got := filed(t, s); got != start {
		t.Errorf("after refused changes: %s, want %s", got, start)
	}
}

func TestAddAndRemoveTag(t *testing.T) {
	s := filedStore(t)
	if n, err := s.AddTag([]vault.Key{pw("a"), pw("c"), pw("a")}, "x"); err != nil || n != 1 {
		t.Errorf("AddTag = %d, %v; want 1 (a already had it)", n, err)
	}
	if n, err := s.RemoveTag([]vault.Key{pw("a"), pw("b"), pw("e")}, "x"); err != nil || n != 2 {
		t.Errorf("RemoveTag = %d, %v; want 2 (e didn't have it)", n, err)
	}
	if got := filed(t, s); got != "a:work: b:work/dev:y c:workshop:x d:job: e::" {
		t.Errorf("after: %s", got)
	}
}

func TestRenameFolder(t *testing.T) {
	s := filedStore(t)
	// Its subfolders go with it; workshop only starts with its name. job is
	// already in use, so the two merge.
	n, merged, err := s.RenameFolder("work", "job")
	if err != nil || n != 2 || !merged {
		t.Fatalf("RenameFolder = %d, %v, %v; want 2, merged", n, merged, err)
	}
	if got := filed(t, s); got != "a:job:x b:job/dev:x,y c:workshop: d:job: e::" {
		t.Errorf("after: %s", got)
	}
	if n, merged, err := s.RenameFolder("job/dev", "Dev"); err != nil || n != 1 || merged {
		t.Errorf("RenameFolder to a new name = %d, %v, %v", n, merged, err)
	}
	for _, tt := range []struct{ from, to, wantSub string }{
		{"nope", "x", `there's no folder "nope"`},
		{"job", "job", "is already called"},
		{"job", "job/old", "into a folder under itself"},
		{"job", "/x", "has an empty part"},
	} {
		if _, _, err := s.RenameFolder(tt.from, tt.to); err == nil || !strings.Contains(err.Error(), tt.wantSub) {
			t.Errorf("RenameFolder(%q, %q) = %v, want %q", tt.from, tt.to, err, tt.wantSub)
		}
	}
	if _, _, err := s.RenameFolder("nope", "x"); !errors.Is(err, vault.ErrNotFound) {
		t.Errorf("a missing folder = %v, want ErrNotFound", err)
	}
}

func TestRenameTag(t *testing.T) {
	s := filedStore(t)
	// b has both x and y: renaming x to y merges them, once each.
	n, merged, err := s.RenameTag("x", "y")
	if err != nil || n != 2 || !merged {
		t.Fatalf("RenameTag = %d, %v, %v; want 2, merged", n, merged, err)
	}
	if got := filed(t, s); got != "a:work:y b:work/dev:y c:workshop: d:job: e::" {
		t.Errorf("after: %s", got)
	}
	if n, merged, err := s.RenameTag("y", "z"); err != nil || n != 2 || merged {
		t.Errorf("RenameTag to a new name = %d, %v, %v", n, merged, err)
	}
	if _, _, err := s.RenameTag("nope", "z"); !errors.Is(err, vault.ErrNotFound) || !strings.Contains(err.Error(), `there's no tag "nope"`) {
		t.Errorf("a missing tag = %v", err)
	}
}

func TestFoldersAndTags(t *testing.T) {
	s := filedStore(t)
	folders, err := s.Folders()
	if err != nil {
		t.Fatal(err)
	}
	want := []FolderCount{{"", 1, 1}, {"job", 1, 1}, {"work", 1, 2}, {"work/dev", 1, 1}, {"workshop", 1, 1}}
	if !slices.Equal(folders, want) {
		t.Errorf("Folders = %+v, want %+v", folders, want)
	}
	tags, untagged, err := s.Tags()
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(tags, []TagCount{{"x", 2}, {"y", 1}}) || untagged != 3 {
		t.Errorf("Tags = %+v, %d untagged", tags, untagged)
	}
}

// A folder above a deep one is listed even with no entries of its own.
func TestFolders_ListsTheFoldersAbove(t *testing.T) {
	s := filedStore(t)
	if err := s.Save(&vault.Entry{Kind: vault.KindPassword, Service: "f", Folder: "deep/er/est"}, []byte("s")); err != nil {
		t.Fatal(err)
	}
	folders, err := s.Folders()
	if err != nil {
		t.Fatal(err)
	}
	want := []FolderCount{{"", 1, 1}, {"deep", 0, 1}, {"deep/er", 0, 1}, {"deep/er/est", 1, 1}, {"job", 1, 1}, {"work", 1, 2}, {"work/dev", 1, 1}, {"workshop", 1, 1}}
	if !slices.Equal(folders, want) {
		t.Errorf("Folders = %+v, want %+v", folders, want)
	}
}
