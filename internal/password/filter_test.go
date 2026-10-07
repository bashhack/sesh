package password

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/bashhack/sesh/internal/kdf"
	"github.com/bashhack/sesh/internal/vault"
)

// filedManager holds entries in folders and with tags.
func filedManager(t *testing.T) *Manager {
	t.Helper()
	m, store := newTestManager(t)
	for _, e := range []*vault.Entry{
		{Kind: vault.KindPassword, Service: "github", Folder: "work/dev", Tags: []string{"code", "urgent"}},
		{Kind: vault.KindPassword, Service: "gitlab", Folder: "work", Tags: []string{"code"}},
		{Kind: vault.KindAPIKey, Service: "openai", Folder: "work"},
		{Kind: vault.KindPassword, Service: "bank", Folder: "personal", Tags: []string{"urgent"}},
		{Kind: vault.KindPassword, Service: "gmail"},
	} {
		if err := store.Save(e, []byte("s")); err != nil {
			t.Fatal(err)
		}
	}
	return m
}

func services(entries []Entry) string {
	names := make([]string, len(entries))
	for i := range entries {
		names[i] = entries[i].Service
	}
	return strings.Join(names, " ")
}

func TestListEntriesFiltered_FolderTagsAndSort(t *testing.T) {
	m := filedManager(t)
	for name, tt := range map[string]struct {
		want   string
		filter ListFilter
	}{
		"a folder and its subfolders": {"github gitlab openai", ListFilter{Folder: "work", FolderSet: true}},
		"no folder":                   {"gmail", ListFilter{FolderSet: true}},
		"a tag":                       {"bank github", ListFilter{Tags: []string{"urgent"}}},
		"every tag":                   {"github", ListFilter{Tags: []string{"urgent", "code"}}},
		"a folder, a tag, a kind":     {"gitlab", ListFilter{Folder: "work", FolderSet: true, Tags: []string{"code"}, EntryType: EntryTypePassword, Service: "GitLab"}},
		"sorted by folder":            {"gmail bank gitlab openai github", ListFilter{SortBy: SortByFolder}},
	} {
		got, err := m.ListEntriesFiltered(&tt.filter)
		if err != nil {
			t.Fatal(err)
		}
		if services(got) != tt.want {
			t.Errorf("%s: %q, want %q", name, services(got), tt.want)
		}
	}
}

func TestSearchIn_KeepsTheFiltersEntries(t *testing.T) {
	m := filedManager(t)
	got, err := m.SearchIn("git", &ListFilter{Folder: "work/dev", FolderSet: true})
	if err != nil || services(got) != "github" {
		t.Errorf("SearchIn = %q, %v; want github", services(got), err)
	}
	// Suggestions come only from the entries the filter lets through.
	if names, err := m.SuggestionsIn("gmial", &ListFilter{Folder: "work", FolderSet: true}); err != nil || len(names) != 0 {
		t.Errorf("SuggestionsIn = %q, %v; want none from outside work", names, err)
	}
}

func TestExport_KeepsTheFiltersEntries(t *testing.T) {
	m := filedManager(t)
	var buf bytes.Buffer
	if n, err := m.Export(&buf, &ExportOptions{Tags: []string{"urgent"}}); err != nil || n != 2 {
		t.Fatalf("Export = %d, %v; want 2", n, err)
	}
	var got []ExportEntry
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil || len(got) != 2 || got[0].Service != "bank" || got[1].Service != "github" {
		t.Errorf("exported %+v, %v; want bank and github", got, err)
	}

	// An encrypted export keeps the same entries.
	buf.Reset()
	if n, err := m.ExportEncrypted(&buf, &ExportOptions{Folder: "personal", FolderSet: true, KDF: kdf.Minimum()}, []byte("export-password")); err != nil || n != 1 {
		t.Errorf("ExportEncrypted by folder = %d, %v; want 1", n, err)
	}
	buf.Reset()
	if n, err := m.ExportEncrypted(&buf, &ExportOptions{Tags: []string{"code"}, KDF: kdf.Minimum()}, []byte("export-password")); err != nil || n != 2 {
		t.Errorf("ExportEncrypted by tag = %d, %v; want 2", n, err)
	}
}

// --sort folder puts each folder's subfolders right after it, whatever
// characters sort before "/".
func TestListEntriesFiltered_SortByFolderKeepsSubfoldersTogether(t *testing.T) {
	m, store := newTestManager(t)
	for i, folder := range []string{"work.archive", "work/dev", "", "work-old", "alpha", "work", "Zed"} {
		if err := store.Save(&vault.Entry{Kind: vault.KindPassword, Service: string(rune('a' + i)), Folder: folder}, []byte("s")); err != nil {
			t.Fatal(err)
		}
	}
	got, err := m.ListEntriesFiltered(&ListFilter{SortBy: SortByFolder})
	if err != nil {
		t.Fatal(err)
	}
	var folders []string
	for i := range got {
		folders = append(folders, got[i].Folder)
	}
	if want := []string{"", "Zed", "alpha", "work", "work/dev", "work-old", "work.archive"}; strings.Join(folders, " | ") != strings.Join(want, " | ") {
		t.Errorf("order %q, want %q", folders, want)
	}
}
