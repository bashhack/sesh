// Package vaulttest is the behaviour every vault.Store must have, as tests
// a Store's own package runs.
package vaulttest

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

// Run checks a Store. newStore returns an empty one.
func Run(t *testing.T, newStore func(t *testing.T) vault.Store) {
	t.Helper()
	gh := vault.Key{Kind: vault.KindPassword, Service: "github", Username: "alice"}
	ghTOTP := vault.Key{Kind: vault.KindTOTP, Service: "github", Username: "alice"}
	openai := vault.Key{Kind: vault.KindAPIKey, Service: "openai"}

	t.Run("put and get", func(t *testing.T) {
		s := newStore(t)
		if err := s.Put(gh, []byte("pw-1")); err != nil {
			t.Fatal(err)
		}
		got, err := s.Get(gh)
		if err != nil || string(got) != "pw-1" {
			t.Fatalf("Get = %q, %v; want pw-1", got, err)
		}
		// The same name in another kind is another entry.
		if _, err := s.Get(ghTOTP); !errors.Is(err, vault.ErrNotFound) {
			t.Errorf("Get of the TOTP entry = %v, want ErrNotFound", err)
		}
	})

	t.Run("put replaces the secret, keeping settings and creation time", func(t *testing.T) {
		s := newStore(t)
		created := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
		settings := vault.Settings{TOTP: totp.Params{Digits: 8, Algorithm: "SHA256"}}
		if err := s.Save(&vault.Entry{Key: ghTOTP, Settings: settings, CreatedAt: created, UpdatedAt: created}, []byte("JBSWY3DPEHPK3PXP")); err != nil {
			t.Fatal(err)
		}
		if err := s.Put(ghTOTP, []byte("NEWSECRETNEWSECR")); err != nil {
			t.Fatal(err)
		}
		e, err := s.Lookup(ghTOTP)
		if err != nil {
			t.Fatal(err)
		}
		if e.Settings != settings || !e.CreatedAt.Equal(created) || !e.UpdatedAt.After(created) {
			t.Errorf("after Put: %+v; want settings %+v kept, created %v kept, updated later", e, settings, created)
		}
		if got, err := s.Get(ghTOTP); err != nil || string(got) != "NEWSECRETNEWSECR" {
			t.Errorf("Get = %q, %v; want the new secret", got, err)
		}
	})

	t.Run("save keeps given times and settings", func(t *testing.T) {
		s := newStore(t)
		created := time.Date(2025, 5, 6, 7, 8, 9, 0, time.UTC)
		updated := time.Date(2025, 6, 7, 8, 9, 10, 0, time.UTC)
		want := vault.Entry{Key: ghTOTP, Settings: vault.Settings{AWSMFADevice: "arn:aws:iam::1:mfa/me"}, CreatedAt: created, UpdatedAt: updated}
		if err := s.Save(&want, []byte("s")); err != nil {
			t.Fatal(err)
		}
		got, err := s.Lookup(ghTOTP)
		if err != nil {
			t.Fatal(err)
		}
		if got.Key != want.Key || got.Settings != want.Settings || !got.CreatedAt.Equal(created) || !got.UpdatedAt.Equal(updated) {
			t.Errorf("Lookup = %+v, want %+v", got, want)
		}
	})

	t.Run("set settings", func(t *testing.T) {
		s := newStore(t)
		if err := s.Put(ghTOTP, []byte("s")); err != nil {
			t.Fatal(err)
		}
		want := vault.Settings{TOTP: totp.Params{Digits: 8}}
		if err := s.SetSettings(ghTOTP, want); err != nil {
			t.Fatal(err)
		}
		if e, err := s.Lookup(ghTOTP); err != nil || e.Settings != want {
			t.Errorf("Lookup = %+v, %v; want settings %+v", e, err, want)
		}
		if err := s.SetSettings(openai, want); !errors.Is(err, vault.ErrNotFound) {
			t.Errorf("SetSettings on a missing entry = %v, want ErrNotFound", err)
		}
	})

	t.Run("list and filter", func(t *testing.T) {
		s := newStore(t)
		for _, k := range []vault.Key{gh, ghTOTP, openai} {
			if err := s.Put(k, []byte("x")); err != nil {
				t.Fatal(err)
			}
		}
		for name, tt := range map[string]struct {
			want string
			f    vault.Filter
		}{
			"all":     {"api_key/openai, password/github/alice, totp/github/alice", vault.Filter{}},
			"kind":    {"totp/github/alice", vault.Filter{Kind: vault.KindTOTP}},
			"service": {"password/github/alice, totp/github/alice", vault.Filter{Service: "github"}},
			"none":    {"", vault.Filter{Service: "nope"}},
		} {
			es, err := s.List(&tt.f)
			if err != nil {
				t.Fatal(err)
			}
			var got []string
			for i := range es {
				got = append(got, es[i].Key.String())
			}
			if strings.Join(got, ", ") != tt.want {
				t.Errorf("%s: List = %v, want %s", name, got, tt.want)
			}
		}
	})

	t.Run("delete", func(t *testing.T) {
		s := newStore(t)
		if err := s.Put(openai, []byte("k")); err != nil {
			t.Fatal(err)
		}
		if err := s.Delete(openai); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Get(openai); !errors.Is(err, vault.ErrNotFound) {
			t.Errorf("Get after Delete = %v, want ErrNotFound", err)
		}
		if err := s.Delete(openai); !errors.Is(err, vault.ErrNotFound) {
			t.Errorf("Delete of a missing entry = %v, want ErrNotFound", err)
		}
	})

	t.Run("delete many", func(t *testing.T) {
		s := newStore(t)
		github := vault.Key{Kind: vault.KindPassword, Service: "github"}
		for _, k := range []vault.Key{openai, github} {
			if err := s.Put(k, []byte("v")); err != nil {
				t.Fatal(err)
			}
		}
		missing := vault.Key{Kind: vault.KindPassword, Service: "missing"}
		if err := s.DeleteMany([]vault.Key{openai, missing}); !errors.Is(err, vault.ErrNotFound) {
			t.Fatalf("with a missing entry: err = %v, want ErrNotFound", err)
		}
		if _, err := s.Lookup(openai); err != nil {
			t.Errorf("an entry was deleted although another was missing: %v", err)
		}
		// A key named twice is deleted once.
		if err := s.DeleteMany([]vault.Key{openai, github, openai}); err != nil {
			t.Fatal(err)
		}
		if es, err := s.List(&vault.Filter{}); err != nil || len(es) != 0 {
			t.Errorf("left %v, %v; want nothing", es, err)
		}
	})

	t.Run("save files the entry; put keeps it filed", func(t *testing.T) {
		s := newStore(t)
		if err := s.Save(&vault.Entry{Key: gh, Folder: "work/dev", Tags: []string{"urgent", "code", "urgent"}}, []byte("pw")); err != nil {
			t.Fatal(err)
		}
		check := func(when, folder string, tags ...string) {
			t.Helper()
			e, err := s.Lookup(gh)
			if err != nil {
				t.Fatal(err)
			}
			listed, err := s.List(&vault.Filter{})
			if err != nil || len(listed) != 1 {
				t.Fatalf("List = %+v, %v", listed, err)
			}
			for _, got := range []*vault.Entry{&e, &listed[0]} {
				if got.Folder != folder || !slices.Equal(got.Tags, tags) {
					t.Errorf("%s: folder %q, tags %q; want %q, %q", when, got.Folder, got.Tags, folder, tags)
				}
			}
		}
		check("after Save", "work/dev", "code", "urgent")
		if err := s.Put(gh, []byte("pw-2")); err != nil {
			t.Fatal(err)
		}
		check("after Put", "work/dev", "code", "urgent")
		// The tags returned are a copy.
		e, err := s.Lookup(gh)
		if err != nil {
			t.Fatal(err)
		}
		e.Tags[0] = "changed"
		check("after changing a returned entry", "work/dev", "code", "urgent")
		if err := s.Save(&vault.Entry{Key: gh, Tags: []string{"later"}}, []byte("pw-3")); err != nil {
			t.Fatal(err)
		}
		check("after Save with another folder and tags", "", "later")
		if err := s.Save(&vault.Entry{Key: gh}, []byte("pw-4")); err != nil {
			t.Fatal(err)
		}
		check("after Save with none", "")
	})

	t.Run("a deleted entry's tags go with it", func(t *testing.T) {
		s := newStore(t)
		if err := s.Save(&vault.Entry{Key: gh, Folder: "work", Tags: []string{"urgent"}}, []byte("pw")); err != nil {
			t.Fatal(err)
		}
		if err := s.Delete(gh); err != nil {
			t.Fatal(err)
		}
		if err := s.Put(gh, []byte("pw")); err != nil {
			t.Fatal(err)
		}
		if e, err := s.Lookup(gh); err != nil || e.Folder != "" || len(e.Tags) != 0 {
			t.Errorf("a new entry with a deleted one's name = %+v, %v; want no folder or tags", e, err)
		}
	})

	t.Run("filter by folder and tags", func(t *testing.T) {
		s := newStore(t)
		for _, e := range []*vault.Entry{
			{Kind: vault.KindPassword, Service: "a", Folder: "work", Tags: []string{"x", "y"}},
			{Kind: vault.KindPassword, Service: "b", Folder: "work/dev", Tags: []string{"x"}},
			{Kind: vault.KindPassword, Service: "c", Folder: "workshop"},
			{Kind: vault.KindPassword, Service: "d", Folder: "Work", Tags: []string{"X"}},
			{Kind: vault.KindPassword, Service: "e", Folder: "a_b"},
			{Kind: vault.KindTOTP, Service: "f", Tags: []string{"y"}},
		} {
			if err := s.Save(e, []byte("v")); err != nil {
				t.Fatal(err)
			}
		}
		for name, tt := range map[string]struct {
			want string
			f    vault.Filter
		}{
			// A folder takes in its subfolders, not a folder that merely
			// starts with its name, and matches case exactly.
			"a folder":           {"a b", vault.Filter{Folder: "work", FolderSet: true}},
			"a subfolder":        {"b", vault.Filter{Folder: "work/dev", FolderSet: true}},
			"another case":       {"d", vault.Filter{Folder: "Work", FolderSet: true}},
			"an underscore":      {"", vault.Filter{Folder: "aXb", FolderSet: true}},
			"no folder":          {"f", vault.Filter{FolderSet: true}},
			"a tag":              {"a b", vault.Filter{Tags: []string{"x"}}},
			"two tags, both":     {"a", vault.Filter{Tags: []string{"x", "y"}}},
			"a tag and a folder": {"b", vault.Filter{Folder: "work/dev", FolderSet: true, Tags: []string{"x"}}},
			"a tag and a kind":   {"f", vault.Filter{Kind: vault.KindTOTP, Tags: []string{"y"}}},
			"no folder or tags":  {"a b c d e f", vault.Filter{}},
		} {
			got, err := s.List(&tt.f)
			if err != nil {
				t.Fatal(err)
			}
			var names []string
			for i := range got {
				names = append(names, got[i].Service)
			}
			if strings.Join(names, " ") != tt.want {
				t.Errorf("%s: List = %q, want %q", name, names, tt.want)
			}
		}
	})

	t.Run("refuses a bad folder or tag", func(t *testing.T) {
		s := newStore(t)
		for _, e := range []*vault.Entry{
			{Key: gh, Folder: "/work"},
			{Key: gh, Folder: "work//dev"},
			{Key: gh, Folder: "work dev"},
			{Key: gh, Tags: []string{""}},
			{Key: gh, Tags: []string{"a,b"}},
			{Key: gh, Tags: []string{strings.Repeat("t", vault.MaxTagLength+1)}},
		} {
			if err := s.Save(e, []byte("v")); err == nil {
				t.Errorf("Save with folder %q, tags %q succeeded, want an error", e.Folder, e.Tags)
			}
		}
		if err := s.Exists(gh); !errors.Is(err, vault.ErrNotFound) {
			t.Errorf("after only refused saves, Exists = %v; want ErrNotFound", err)
		}
	})

	t.Run("refuses a bad key", func(t *testing.T) {
		s := newStore(t)
		for _, k := range []vault.Key{
			{Kind: "bogus", Service: "x"},
			{Kind: vault.KindPassword},
			{Kind: vault.KindPassword, Service: "a/b"},
			{Kind: vault.KindPassword, Service: "x", Username: "a\nb"},
			{Kind: vault.KindPassword, Service: "github "},
			{Kind: vault.KindPassword, Service: "x", Username: " alice"},
			{Kind: vault.KindPassword, Service: strings.Repeat("x", vault.MaxNameLength+1)},
		} {
			if err := s.Put(k, []byte("v")); err == nil {
				t.Errorf("Put(%+v) succeeded, want an error", k)
			}
			if err := s.Save(&vault.Entry{Key: k}, []byte("v")); err == nil {
				t.Errorf("Save(%+v) succeeded, want an error", k)
			}
			// A bad key is never stored, so reading or changing it finds nothing.
			if _, err := s.Get(k); !errors.Is(err, vault.ErrNotFound) {
				t.Errorf("Get(%+v) = %v, want ErrNotFound", k, err)
			}
			if _, err := s.Lookup(k); !errors.Is(err, vault.ErrNotFound) {
				t.Errorf("Lookup(%+v) = %v, want ErrNotFound", k, err)
			}
			if err := s.SetSettings(k, vault.Settings{}); !errors.Is(err, vault.ErrNotFound) {
				t.Errorf("SetSettings(%+v) = %v, want ErrNotFound", k, err)
			}
			if err := s.Delete(k); !errors.Is(err, vault.ErrNotFound) {
				t.Errorf("Delete(%+v) = %v, want ErrNotFound", k, err)
			}
			if _, err := s.Details(k, "all"); !errors.Is(err, vault.ErrNotFound) {
				t.Errorf("Details(%+v) = %v, want ErrNotFound", k, err)
			}
		}
	})

	details := func() vault.Details {
		return vault.Details{
			URL:   "https://github.com/login",
			Notes: []byte("line one\nline two"),
			Fields: []vault.Field{
				{Name: "recovery-email", Value: []byte("alice@example.com")},
				{Name: "pin", Value: []byte("1234"), Secret: true},
				{Name: "backup.code", Value: []byte("a\tb\nc"), Secret: true},
			},
		}
	}

	t.Run("details: set and read back", func(t *testing.T) {
		s := newStore(t)
		if err := s.Put(gh, []byte("pw")); err != nil {
			t.Fatal(err)
		}
		if d, err := s.Details(gh, "all"); err != nil || !d.IsZero() {
			t.Fatalf("Details of a new entry = %+v, %v; want none", d, err)
		}
		want := details()
		if err := s.SetDetails(gh, &want); err != nil {
			t.Fatal(err)
		}
		got, err := s.Details(gh, "all")
		if err != nil {
			t.Fatal(err)
		}
		checkDetails(t, &got, &want)
		// What's readable without the key: the URL, that there are notes,
		// and the fields in order, with only the plain values.
		e, err := s.Lookup(gh)
		if err != nil {
			t.Fatal(err)
		}
		wantFields := []vault.Field{{Name: "recovery-email", Value: []byte("alice@example.com")}, {Name: "pin", Secret: true}, {Name: "backup.code", Secret: true}}
		if e.URL != want.URL || !e.HasNotes || !fieldsEqual(e.Fields, wantFields) {
			t.Errorf("Lookup = URL %q, notes %v, fields %+v; want %q, true, %+v", e.URL, e.HasNotes, e.Fields, want.URL, wantFields)
		}
		list, err := s.List(&vault.Filter{})
		if err != nil || len(list) != 1 || list[0].URL != want.URL || !list[0].HasNotes || !fieldsEqual(list[0].Fields, wantFields) {
			t.Errorf("List = %+v, %v; want the details as Lookup has them", list, err)
		}
		// Replacing them replaces all of it.
		if err := s.SetDetails(gh, &vault.Details{URL: "https://example.com"}); err != nil {
			t.Fatal(err)
		}
		got, err = s.Details(gh, "all")
		if err != nil {
			t.Fatal(err)
		}
		checkDetails(t, &got, &vault.Details{URL: "https://example.com"})
		if e, _ := s.Lookup(gh); e.HasNotes || len(e.Fields) != 0 { //nolint:errcheck // checked by Details above
			t.Errorf("Lookup after replacing = notes %v, fields %+v; want none", e.HasNotes, e.Fields)
		}
	})

	t.Run("details: setting them keeps the update time; saving with them replaces them", func(t *testing.T) {
		s := newStore(t)
		made := time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC)
		if err := s.Save(&vault.Entry{Key: gh, CreatedAt: made, UpdatedAt: made}, []byte("pw")); err != nil {
			t.Fatal(err)
		}
		want := details()
		if err := s.SetDetails(gh, &want); err != nil {
			t.Fatal(err)
		}
		if e, err := s.Lookup(gh); err != nil || !e.UpdatedAt.Equal(made) {
			t.Errorf("update time after SetDetails = %v, %v; want %v kept", e.UpdatedAt, err, made)
		}
		// SaveWithDetails writes the entry and its details together,
		// replacing what was there; none removes them.
		if err := s.SaveWithDetails(&vault.Entry{Key: gh, Folder: "work"}, []byte("pw-2"), &vault.Details{URL: "https://new.example"}); err != nil {
			t.Fatal(err)
		}
		got, err := s.Details(gh, "all")
		if err != nil {
			t.Fatal(err)
		}
		checkDetails(t, &got, &vault.Details{URL: "https://new.example"})
		if err := s.SaveWithDetails(&vault.Entry{Key: gh}, []byte("pw-3"), &vault.Details{}); err != nil {
			t.Fatal(err)
		}
		if d, err := s.Details(gh, "all"); err != nil || !d.IsZero() {
			t.Errorf("Details after saving with none = %+v, %v", d, err)
		}
		// Details the entry can't have are refused, and nothing is saved.
		newKey := vault.Key{Kind: vault.KindNote, Service: "new"}
		if err := s.SaveWithDetails(&vault.Entry{Key: newKey}, []byte("n"), &vault.Details{Notes: []byte("x")}); err == nil {
			t.Error("SaveWithDetails with notes on a secure note succeeded")
		}
		if err := s.Exists(newKey); !errors.Is(err, vault.ErrNotFound) {
			t.Errorf("the refused entry was saved: %v", err)
		}
	})

	t.Run("details: put and save keep them, delete removes them", func(t *testing.T) {
		s := newStore(t)
		if err := s.Put(gh, []byte("pw")); err != nil {
			t.Fatal(err)
		}
		want := details()
		if err := s.SetDetails(gh, &want); err != nil {
			t.Fatal(err)
		}
		if err := s.Put(gh, []byte("pw-2")); err != nil {
			t.Fatal(err)
		}
		if err := s.Save(&vault.Entry{Key: gh, Folder: "work"}, []byte("pw-3")); err != nil {
			t.Fatal(err)
		}
		got, err := s.Details(gh, "all")
		if err != nil {
			t.Fatal(err)
		}
		checkDetails(t, &got, &want)
		if err := s.Delete(gh); err != nil {
			t.Fatal(err)
		}
		if err := s.Put(gh, []byte("pw")); err != nil {
			t.Fatal(err)
		}
		if d, err := s.Details(gh, "all"); err != nil || !d.IsZero() {
			t.Errorf("Details after delete and put = %+v, %v; want none", d, err)
		}
	})

	t.Run("details: refused", func(t *testing.T) {
		s := newStore(t)
		note := vault.Key{Kind: vault.KindNote, Service: "wifi"}
		for _, k := range []vault.Key{gh, note} {
			if err := s.Put(k, []byte("v")); err != nil {
				t.Fatal(err)
			}
		}
		tests := []struct {
			k       vault.Key
			wantSub string
			d       vault.Details
		}{
			{note, "a secure note can't have notes", vault.Details{Notes: []byte("n")}},
			{gh, "the URL contains a control character", vault.Details{URL: "https://a\nb"}},
			{gh, "the URL is 2049 characters long", vault.Details{URL: strings.Repeat("x", vault.MaxURLLength+1)}},
			{gh, `the field name "url" is reserved`, vault.Details{Fields: []vault.Field{{Name: "url", Value: []byte("v")}}}},
			{gh, `the field name "Notes" is reserved`, vault.Details{Fields: []vault.Field{{Name: "Notes", Value: []byte("v")}}}},
			{gh, `the field name "my pin" contains ' '`, vault.Details{Fields: []vault.Field{{Name: "my pin", Value: []byte("v")}}}},
			{gh, `the field "pin" is there twice`, vault.Details{Fields: []vault.Field{{Name: "pin", Value: []byte("1")}, {Name: "pin", Value: []byte("2"), Secret: true}}}},
			{gh, `the field "pin" has no value`, vault.Details{Fields: []vault.Field{{Name: "pin", Secret: true}}}},
			{gh, `the field "host" contains a control character`, vault.Details{Fields: []vault.Field{{Name: "host", Value: []byte("a\tb")}}}},
			{gh, `the field "PIN" is there twice (as "pin")`, vault.Details{Fields: []vault.Field{{Name: "pin", Value: []byte("1")}, {Name: "PIN", Value: []byte("2")}}}},
			{gh, "the notes aren't valid text", vault.Details{Notes: []byte{0xff, 'x'}}},
			{gh, `the field "pin" isn't valid text`, vault.Details{Fields: []vault.Field{{Name: "pin", Value: []byte{0xfe}, Secret: true}}}},
			{gh, `the notes contain a control character, "\x1b" on line 2`, vault.Details{Notes: []byte("ok\nhi\x1b]0;title\x07")}},
			{gh, `the notes contain a control character, "\r" on line 1`, vault.Details{Notes: []byte("real\rFAKE")}},
			{gh, `the field "pin" contains a control character`, vault.Details{Fields: []vault.Field{{Name: "pin", Value: []byte("\x1b[31m"), Secret: true}}}},
			{gh, "take 1048577 bytes together", vault.Details{Notes: bytes.Repeat([]byte("a"), vault.MaxDetailsSize), Fields: []vault.Field{{Name: "pin", Value: []byte("1"), Secret: true}}}},
		}
		for i := range tests {
			tc := &tests[i]
			if err := s.SetDetails(tc.k, &tc.d); err == nil || !strings.Contains(err.Error(), tc.wantSub) {
				t.Errorf("SetDetails(%s, %+v) = %v, want an error containing %q", tc.k, tc.d.Fields, err, tc.wantSub)
			}
		}
		many := vault.Details{}
		for i := range vault.MaxFields + 1 {
			many.Fields = append(many.Fields, vault.Field{Name: "f" + strings.Repeat("x", i), Value: []byte("v")})
		}
		if err := s.SetDetails(gh, &many); err == nil || !strings.Contains(err.Error(), "at most 50 fields") {
			t.Errorf("SetDetails with %d fields = %v, want refused", len(many.Fields), err)
		}
		// A secure note still takes a URL and fields.
		if err := s.SetDetails(note, &vault.Details{URL: "https://router.local", Fields: []vault.Field{{Name: "ssid", Value: []byte("home")}}}); err != nil {
			t.Errorf("SetDetails on a secure note: %v", err)
		}
		if err := s.SetDetails(vault.Key{Kind: vault.KindPassword, Service: "nope"}, &vault.Details{URL: "x"}); !errors.Is(err, vault.ErrNotFound) {
			t.Errorf("SetDetails of a missing entry = %v, want ErrNotFound", err)
		}
	})
}

// checkDetails fails t unless got is want.
func checkDetails(t *testing.T, got, want *vault.Details) {
	t.Helper()
	if got.URL != want.URL || !bytes.Equal(got.Notes, want.Notes) || !fieldsEqual(got.Fields, want.Fields) {
		t.Errorf("details = %+v (notes %q), want %+v (notes %q)", got, got.Notes, want, want.Notes)
	}
}

func fieldsEqual(a, b []vault.Field) bool {
	return slices.EqualFunc(a, b, func(x, y vault.Field) bool {
		return x.Name == y.Name && x.Secret == y.Secret && bytes.Equal(x.Value, y.Value)
	})
}
