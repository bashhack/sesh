// Package vaulttest is the behaviour every vault.Store must have, as tests
// a Store's own package runs.
package vaulttest

import (
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
			f    vault.Filter
			want string
		}{
			"all":     {vault.Filter{}, "api_key/openai, password/github/alice, totp/github/alice"},
			"kind":    {vault.Filter{Kind: vault.KindTOTP}, "totp/github/alice"},
			"service": {vault.Filter{Service: "github"}, "password/github/alice, totp/github/alice"},
			"none":    {vault.Filter{Service: "nope"}, ""},
		} {
			es, err := s.List(tt.f)
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
		if es, err := s.List(vault.Filter{}); err != nil || len(es) != 0 {
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
			listed, err := s.List(vault.Filter{})
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
		}
	})
}
