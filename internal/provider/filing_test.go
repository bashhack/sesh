package provider

import (
	"testing"

	"github.com/bashhack/sesh/internal/vault"
)

func TestNoMatchHint(t *testing.T) {
	store := vault.NewMemStore()
	for _, e := range []*vault.Entry{
		{Kind: vault.KindPassword, Service: "a", Folder: "work/dev", Tags: []string{"code"}},
		{Kind: vault.KindPassword, Service: "b", Folder: "Personal", Tags: []string{"Urgent"}},
	} {
		if err := store.Save(e, []byte("s")); err != nil {
			t.Fatal(err)
		}
	}
	for name, tt := range map[string]struct {
		want string
		f    vault.Filter
	}{
		"a parent folder exists": {"", vault.Filter{Folder: "work", FolderSet: true, Tags: []string{"code"}}},
		"a twin, then a miss":    {`there's no tag "urgent"; did you mean Urgent?; there's no tag "x". Folders and tags are case-sensitive`, vault.Filter{Tags: []string{"urgent", "x"}}},
		"only by case":           {`there's no folder "work/Dev"; did you mean work/dev? Folders and tags are case-sensitive`, vault.Filter{Folder: "work/Dev", FolderSet: true}},
		"a tag only by case":     {`there's no tag "urgent"; did you mean Urgent? Folders and tags are case-sensitive`, vault.Filter{Tags: []string{"urgent"}}},
		"neither, no twin":       {`there's no folder "home"; there's no tag "x"`, vault.Filter{Folder: "home", FolderSet: true, Tags: []string{"x"}}},
		"no folder asked for":    {"", vault.Filter{FolderSet: true}},
		"both exist, no match":   {"", vault.Filter{Folder: "Personal", FolderSet: true, Tags: []string{"code"}}},
	} {
		if got := NoMatchHint(store, &tt.f); got != tt.want {
			t.Errorf("%s: %q, want %q", name, got, tt.want)
		}
	}
}
