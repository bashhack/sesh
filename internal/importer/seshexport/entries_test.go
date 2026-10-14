package seshexport

import (
	"strings"
	"testing"
	"time"

	"github.com/bashhack/sesh/internal/password"
	"github.com/bashhack/sesh/internal/vault"
)

// Each entry comes with its secret, details, filing, settings and times; one sesh can't hold is skipped, saying why.
func TestEntries(t *testing.T) {
	made := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	got := Entries([]password.ExportEntry{
		{Service: "github", Username: "alice", Type: vault.KindPassword, Secret: "s3cret", Folder: "Work", Tags: []string{"dev"},
			URL: "https://github.com", Notes: "n", Fields: []password.ExportField{{Name: "pin", Value: "1234", Secret: true}}, CreatedAt: made, UpdatedAt: made.Add(time.Hour),
			Settings: vault.Settings{AWSMFADevice: "arn:aws:iam::1:mfa/x"}},
		{Service: "", Type: vault.KindPassword, Secret: "x"},
		{Service: "empty", Type: vault.KindPassword},
		{Service: "odd", Type: "card", Secret: "x"},
		{Service: "bad folder", Type: vault.KindPassword, Secret: "x", Folder: "a//b"},
	})
	if len(got) != 5 {
		t.Fatalf("%d entries", len(got))
	}
	e := got[0]
	if e.Skip != "" || e.Key != (vault.Key{Kind: vault.KindPassword, Service: "github", Username: "alice"}) || string(e.Secret) != "s3cret" ||
		e.Folder != "Work" || len(e.Tags) != 1 || e.Details.URL != "https://github.com" || string(e.Details.Notes) != "n" ||
		len(e.Details.Fields) != 1 || !e.Details.Fields[0].Secret || !e.Created.Equal(made) || !e.Updated.Equal(made.Add(time.Hour)) ||
		e.Settings.AWSMFADevice != "arn:aws:iam::1:mfa/x" || e.Name != "github (alice)" {
		t.Errorf("the entry: %+v", e)
	}
	for i, wantSub := range map[int]string{1: "no name", 2: "no secret", 3: `its kind, "card", isn't one sesh has`, 4: "folder"} {
		if !strings.Contains(got[i].Skip, wantSub) {
			t.Errorf("entry %d skipped for %q, want %q", i, got[i].Skip, wantSub)
		}
	}
}
