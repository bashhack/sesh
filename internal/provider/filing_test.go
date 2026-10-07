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
		{Kind: vault.KindPassword, Service: "c", Folder: "café"},
		{Kind: vault.KindTOTP, Service: "d", Folder: "home"},
	} {
		if err := store.Save(e, []byte("s")); err != nil {
			t.Fatal(err)
		}
	}
	const cs = ". Folders and tags are case-sensitive"
	for name, tt := range map[string]struct {
		want, among string
		f           vault.Filter
	}{
		"a parent folder exists": {want: "", f: vault.Filter{Folder: "work", FolderSet: true, Tags: []string{"code"}}},
		"only by case":           {want: `there's no folder "work/Dev" (did you mean "work/dev"?)` + cs, f: vault.Filter{Folder: "work/Dev", FolderSet: true}},
		"a tag only by case":     {want: `there's no tag "urgent" (did you mean "Urgent"?)` + cs, f: vault.Filter{Tags: []string{"urgent"}}},
		"a twin, then a miss":    {want: `there's no folder "Work" (did you mean "work"?); there's no tag "x"` + cs, f: vault.Filter{Folder: "Work", FolderSet: true, Tags: []string{"x"}}},
		"neither, no twin":       {want: `there's no folder "nope"; there's no tag "x"`, f: vault.Filter{Folder: "nope", FolderSet: true, Tags: []string{"x"}}},
		"no folder asked for":    {want: "", f: vault.Filter{FolderSet: true}},
		"both exist, no match":   {want: "", f: vault.Filter{Folder: "Personal", FolderSet: true, Tags: []string{"code"}}},
		// An accent written as its own character looks the same but isn't.
		"another spelling": {want: `there's no folder "cafe\u0301" (did you mean "café"?)` + cs, f: vault.Filter{Folder: "cafe\u0301", FolderSet: true}},
		// Only the kind's entries count: work holds passwords, not TOTP.
		"another kind's folder": {want: `there's no folder "work" among TOTP entries`, among: "TOTP entries", f: vault.Filter{Kind: vault.KindTOTP, Folder: "work", FolderSet: true}},
		"the kind's own folder": {want: "", among: "TOTP entries", f: vault.Filter{Kind: vault.KindTOTP, Folder: "home", FolderSet: true}},
	} {
		if got := NoMatchHint(store, &tt.f, tt.among); got != tt.want {
			t.Errorf("%s: %q, want %q", name, got, tt.want)
		}
	}
}

func TestScope(t *testing.T) {
	for want, f := range map[string]vault.Filter{
		"":                 {},
		`in folder "work"`: {Folder: "work", FolderSet: true},
		"in no folder":     {FolderSet: true},
		`with tag "a"`:     {Tags: []string{"a"}},
		`in folder "w" with tags "a", "b" and "c"`: {Folder: "w", FolderSet: true, Tags: []string{"a", "b", "c"}},
	} {
		if got := Scope(&f); got != want {
			t.Errorf("Scope(%+v) = %q, want %q", f, got, want)
		}
	}
}
