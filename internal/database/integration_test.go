package database

import (
	"bytes"
	"encoding/json"
	"fmt"
	"image/png"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	otplib "github.com/pquerna/otp/totp"

	"github.com/bashhack/sesh/internal/password"
	"github.com/bashhack/sesh/internal/qrcode"
	"github.com/bashhack/sesh/internal/secure"
	"github.com/bashhack/sesh/internal/totp"
	"github.com/bashhack/sesh/internal/vault"
)

// newIntegrationStore creates a real SQLite store with real encryption for integration tests.
func newIntegrationStore(t *testing.T) (*Store, *password.Manager) {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "integration.db")
	key, err := GenerateEncryptionKey()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { secure.SecureZeroBytes(key) })

	store, err := Open(dbPath, &mockKeySource{key: key})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Errorf("store.Close: %v", err)
		}
	})

	if err := store.InitKeyMetadata(); err != nil {
		t.Fatal(err)
	}

	mgr := password.NewManager(store)
	return store, mgr
}

func TestIntegration_PasswordCRUD(t *testing.T) {
	_, mgr := newIntegrationStore(t)

	// Store
	t.Log("Store passwords")
	if err := mgr.StorePasswordString("github", "alice", "gh-secret-123", password.EntryTypePassword); err != nil {
		t.Fatal(err)
	}
	if err := mgr.StorePasswordString("github", "bob", "gh-bob-456", password.EntryTypePassword); err != nil {
		t.Fatal(err)
	}
	t.Log("  Stored github/alice, github/bob")

	// Retrieve
	t.Log("Retrieve")
	pw, err := mgr.GetPasswordString("github", "alice", password.EntryTypePassword)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("  github/alice = %q", pw)
	if pw != "gh-secret-123" {
		t.Fatalf("expected 'gh-secret-123', got %q", pw)
	}

	// Update (upsert)
	t.Log("Update github/alice")
	if err := mgr.StorePasswordString("github", "alice", "new-secret-999", password.EntryTypePassword); err != nil {
		t.Fatal(err)
	}
	pw, err = mgr.GetPasswordString("github", "alice", password.EntryTypePassword)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("  Updated: %q", pw)
	if pw != "new-secret-999" {
		t.Fatalf("expected 'new-secret-999', got %q", pw)
	}

	// Delete
	t.Log("Delete github/bob")
	if err := mgr.DeleteEntry("github", "bob", password.EntryTypePassword); err != nil {
		t.Fatal(err)
	}
	_, err = mgr.GetPassword("github", "bob", password.EntryTypePassword)
	if err == nil {
		t.Fatal("expected error after delete")
	}
	t.Log("  Confirmed deleted")
}

func TestIntegration_APIKeys(t *testing.T) {
	_, mgr := newIntegrationStore(t)

	t.Log("Store API key")
	if err := mgr.StorePasswordString("stripe", "admin", "sk_live_abc123", password.EntryTypeAPIKey); err != nil {
		t.Fatal(err)
	}

	pw, err := mgr.GetPasswordString("stripe", "admin", password.EntryTypeAPIKey)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("  stripe/admin = %q", pw)
	if pw != "sk_live_abc123" {
		t.Fatalf("expected 'sk_live_abc123', got %q", pw)
	}

	// Verify it shows up in list with correct type
	entries, err := mgr.ListEntriesFiltered(password.ListFilter{EntryType: password.EntryTypeAPIKey})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("  API key entries: %d", len(entries))
	if len(entries) != 1 {
		t.Fatalf("expected 1 api_key entry, got %d", len(entries))
	}
	if entries[0].Type != password.EntryTypeAPIKey {
		t.Fatalf("expected type api_key, got %s", entries[0].Type)
	}
}

func TestIntegration_SecureNotes(t *testing.T) {
	_, mgr := newIntegrationStore(t)

	note := "Recovery codes for GitHub:\n1. abc-123-def\n2. ghi-456-jkl\n3. mno-789-pqr\n\nStored on 2026-04-06. Do NOT share."
	t.Log("Store secure note")
	if err := mgr.StorePasswordString("github", "recovery-codes", note, password.EntryTypeNote); err != nil {
		t.Fatal(err)
	}

	// Retrieve round-trip
	t.Log("Retrieve")
	retrieved, err := mgr.GetPasswordString("github", "recovery-codes", password.EntryTypeNote)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("  Retrieved %d bytes", len(retrieved))
	if retrieved != note {
		t.Fatalf("note round-trip failed:\n  got:  %q\n  want: %q", retrieved, note)
	}

	// Also store a password so we can verify type filtering
	if err := mgr.StorePasswordString("github", "alice", "pw1", password.EntryTypePassword); err != nil {
		t.Fatal(err)
	}

	// List filtered by note type
	t.Log("List filtered by secure_note")
	filtered, err := mgr.ListEntriesFiltered(password.ListFilter{EntryType: password.EntryTypeNote})
	if err != nil {
		t.Fatal(err)
	}
	if len(filtered) != 1 {
		t.Fatalf("expected 1 note, got %d", len(filtered))
	}
	if filtered[0].Type != password.EntryTypeNote {
		t.Fatalf("expected type secure_note, got %s", filtered[0].Type)
	}
	t.Logf("  Found: %s/%s [%s]", filtered[0].Service, filtered[0].Username, filtered[0].Type)

	// Search finds the note by its username
	t.Log("Search for 'recovery'")
	results, err := mgr.SearchEntries("recovery")
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 search result, got %d", len(results))
	}
	t.Logf("  Found: %s/%s", results[0].Service, results[0].Username)

	// Update note
	t.Log("Update note")
	updatedNote := note + "\n4. stu-012-vwx (added later)"
	if err := mgr.StorePasswordString("github", "recovery-codes", updatedNote, password.EntryTypeNote); err != nil {
		t.Fatal(err)
	}
	retrieved, err = mgr.GetPasswordString("github", "recovery-codes", password.EntryTypeNote)
	if err != nil {
		t.Fatal(err)
	}
	if retrieved != updatedNote {
		t.Fatalf("update failed")
	}
	t.Logf("  Updated to %d bytes", len(retrieved))

	// Delete
	t.Log("Delete note")
	if err := mgr.DeleteEntry("github", "recovery-codes", password.EntryTypeNote); err != nil {
		t.Fatal(err)
	}
	_, err = mgr.GetPassword("github", "recovery-codes", password.EntryTypeNote)
	if err == nil {
		t.Fatal("expected error after delete")
	}
	t.Log("  Confirmed deleted")
}

func TestIntegration_TOTP(t *testing.T) {
	_, mgr := newIntegrationStore(t)

	// Store TOTP secret (validates and normalizes)
	t.Log("Store TOTP secret")
	if err := mgr.StoreTOTPSecret("aws", "root", "JBSWY3DPEHPK3PXP"); err != nil {
		t.Fatal(err)
	}
	t.Log("  Stored aws/root")

	// Generate code
	t.Log("Generate TOTP code")
	code, err := mgr.GenerateTOTPCode("aws", "root")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("  Code: %s (len=%d)", code, len(code))
	if len(code) != 6 {
		t.Fatalf("expected 6-digit code, got %q", code)
	}
	for _, c := range code {
		if c < '0' || c > '9' {
			t.Fatalf("expected numeric code, got %q", code)
		}
	}

	// Invalid secret should fail
	t.Log("Store invalid TOTP secret")
	err = mgr.StoreTOTPSecret("bad", "user", "not-valid-base32!!!")
	if err == nil {
		t.Fatal("expected error for invalid TOTP secret")
	}
	t.Logf("  Correctly rejected: %v", err)
}

func TestIntegration_ListFilterSort(t *testing.T) {
	_, mgr := newIntegrationStore(t)

	// Seed mixed entry types
	for _, e := range []struct {
		svc, user, pw string
		typ           password.EntryType
	}{
		{"github", "alice", "pw1", password.EntryTypePassword},
		{"stripe", "admin", "key1", password.EntryTypeAPIKey},
		{"gitlab", "bob", "pw2", password.EntryTypePassword},
		{"aws", "root", "JBSWY3DPEHPK3PXP", password.EntryTypeTOTP},
		{"notes", "recovery", "codes", password.EntryTypeNote},
	} {
		if err := mgr.StorePasswordString(e.svc, e.user, e.pw, e.typ); err != nil {
			t.Fatal(err)
		}
	}

	// All entries
	t.Log("All entries")
	all, err := mgr.ListEntries()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("  Total: %d", len(all))
	if len(all) != 5 {
		t.Fatalf("expected 5, got %d", len(all))
	}

	// Filter by type
	t.Log("Filter: password only")
	passwords, err := mgr.ListEntriesFiltered(password.ListFilter{EntryType: password.EntryTypePassword})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("  Passwords: %d", len(passwords))
	if len(passwords) != 2 {
		t.Fatalf("expected 2 passwords, got %d", len(passwords))
	}

	// Filter by service
	t.Log("Filter: service=github")
	byService, err := mgr.GetPasswordsByService("github")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("  GitHub entries: %d", len(byService))
	if len(byService) != 1 {
		t.Fatalf("expected 1, got %d", len(byService))
	}

	// Pagination
	t.Log("Pagination: limit=2, offset=1")
	page, err := mgr.ListEntriesFiltered(password.ListFilter{Limit: 2, Offset: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("  Page: %d entries", len(page))
	if len(page) != 2 {
		t.Fatalf("expected 2, got %d", len(page))
	}

	// Offset beyond end
	t.Log("Pagination: offset=100")
	empty, err := mgr.ListEntriesFiltered(password.ListFilter{Offset: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(empty) != 0 {
		t.Fatalf("expected 0, got %d", len(empty))
	}
}

func TestIntegration_Search(t *testing.T) {
	_, mgr := newIntegrationStore(t)

	if err := mgr.StorePasswordString("github", "alice", "pw1", password.EntryTypePassword); err != nil {
		t.Fatal(err)
	}
	if err := mgr.StorePasswordString("gitlab", "alice", "pw2", password.EntryTypePassword); err != nil {
		t.Fatal(err)
	}
	if err := mgr.StorePasswordString("stripe", "admin", "key1", password.EntryTypeAPIKey); err != nil {
		t.Fatal(err)
	}

	for query, want := range map[string][]string{
		"git":         {"github", "gitlab"},
		"hub":         {"github"},
		"admin":       {"stripe"},
		"gitops":      nil,
		"password":    {"github", "gitlab"}, // names the kind
		"key":         {"stripe"},
		"nonexistent": nil,
	} {
		results, err := mgr.SearchEntries(query)
		if err != nil {
			t.Fatalf("SearchEntries(%q): %v", query, err)
		}
		var got []string
		for _, e := range results {
			got = append(got, e.Service)
		}
		slices.Sort(got) // the order is covered by the password package's tests
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("SearchEntries(%q) = %v, want %v", query, got, want)
		}
	}
}

func TestIntegration_AuditLog(t *testing.T) {
	store, mgr := newIntegrationStore(t)

	if err := mgr.StorePasswordString("github", "alice", "pw1", password.EntryTypePassword); err != nil {
		t.Fatal(err)
	}
	if _, err := mgr.GetPassword("github", "alice", password.EntryTypePassword); err != nil {
		t.Fatal(err)
	}
	if err := mgr.DeleteEntry("github", "alice", password.EntryTypePassword); err != nil {
		t.Fatal(err)
	}

	var count int
	if err := store.db.QueryRow("SELECT COUNT(*) FROM audit_log").Scan(&count); err != nil {
		t.Fatal(err)
	}
	t.Logf("Audit events after store+get+delete: %d", count)
	if count < 3 {
		t.Fatalf("expected at least 3 audit events, got %d", count)
	}

	rows, err := store.db.Query("SELECT event_type, entry_id, detail FROM audit_log ORDER BY id")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := rows.Close(); err != nil {
			t.Errorf("rows.Close: %v", err)
		}
	}()
	for rows.Next() {
		var evType, entryID, detail string
		if err := rows.Scan(&evType, &entryID, &detail); err != nil {
			t.Fatal(err)
		}
		t.Logf("  %-8s %-50s %s", evType, entryID, detail)
	}
}

func TestIntegration_JSONOutput(t *testing.T) {
	_, mgr := newIntegrationStore(t)

	if err := mgr.StorePasswordString("github", "alice", "pw1", password.EntryTypePassword); err != nil {
		t.Fatal(err)
	}
	if err := mgr.StorePasswordString("stripe", "admin", "key1", password.EntryTypeAPIKey); err != nil {
		t.Fatal(err)
	}

	entries, err := mgr.ListEntries()
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("JSON:\n%s", string(b))

	// Verify it round-trips
	var parsed []password.Entry
	if err := json.Unmarshal(b, &parsed); err != nil {
		t.Fatalf("JSON round-trip failed: %v", err)
	}
	if len(parsed) != 2 {
		t.Fatalf("expected 2 entries in JSON, got %d", len(parsed))
	}
}

// --- The entries the AWS and TOTP providers keep, through the vault ---

func TestIntegration_AWSTOTPWorkflow(t *testing.T) {
	store, _ := newIntegrationStore(t)
	secret := []byte("JBSWY3DPEHPK3PXP")
	device := "arn:aws:iam::123456789012:mfa/alice"

	// AWS setup stores a profile's MFA secret with its device, in one entry.
	t.Log("Store AWS MFA secret and device")
	if err := store.Save(&vault.Entry{Key: vault.AWSKey("production"), Settings: vault.Settings{AWSMFADevice: device}}, secret); err != nil {
		t.Fatal(err)
	}

	got, err := store.Get(vault.AWSKey("production"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(secret) {
		t.Fatalf("expected %q, got %q", secret, got)
	}
	e, err := store.Lookup(vault.AWSKey("production"))
	if err != nil || e.Settings.AWSMFADevice != device {
		t.Fatalf("Lookup = %+v, %v; want the device %s", e.Settings, err, device)
	}

	// A second profile, and an unrelated TOTP entry the AWS list leaves out.
	if err := store.Put(vault.AWSKey("staging"), []byte("AAAAAAAAAAAAAAAA")); err != nil {
		t.Fatal(err)
	}
	if err := store.Put(vault.Key{Kind: vault.KindTOTP, Service: "github"}, secret); err != nil {
		t.Fatal(err)
	}
	entries, err := store.List(vault.Filter{Kind: vault.KindTOTP, Service: "aws"})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 || entries[0].Username != "production" || entries[1].Username != "staging" {
		t.Fatalf("AWS entries = %+v, want production and staging", entries)
	}
}

func TestIntegration_GenericTOTPWorkflow(t *testing.T) {
	store, _ := newIntegrationStore(t)
	secret := []byte("JBSWY3DPEHPK3PXP")
	keys := []vault.Key{
		{Kind: vault.KindTOTP, Service: "github"},
		{Kind: vault.KindTOTP, Service: "gitlab", Username: "work"},
		{Kind: vault.KindTOTP, Service: "aws-console"},
	}
	for _, k := range keys {
		if err := store.Put(k, secret); err != nil {
			t.Fatal(err)
		}
	}

	got, err := store.Get(keys[0])
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(secret) {
		t.Fatalf("expected %q, got %q", secret, got)
	}

	entries, err := store.List(vault.Filter{Kind: vault.KindTOTP})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 {
		t.Fatalf("expected 3 TOTP entries, got %d", len(entries))
	}

	if err := store.Delete(keys[1]); err != nil {
		t.Fatal(err)
	}
	entries, err = store.List(vault.Filter{Kind: vault.KindTOTP})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 after delete, got %d", len(entries))
	}
}

func TestIntegration_KindIsolation(t *testing.T) {
	store, _ := newIntegrationStore(t)
	for _, k := range []vault.Key{
		vault.AWSKey("prod"),
		{Kind: vault.KindTOTP, Service: "github"},
		{Kind: vault.KindPassword, Service: "stripe", Username: "admin"},
		{Kind: vault.KindPassword, Service: "aws", Username: "prod"}, // same name as the AWS entry, another kind
	} {
		if err := store.Put(k, []byte("x")); err != nil {
			t.Fatal(err)
		}
	}

	tests := map[string]struct {
		filter   vault.Filter
		expected int
	}{
		"totp":         {filter: vault.Filter{Kind: vault.KindTOTP}, expected: 2},
		"password":     {filter: vault.Filter{Kind: vault.KindPassword}, expected: 2},
		"aws profiles": {filter: vault.Filter{Kind: vault.KindTOTP, Service: "aws"}, expected: 1},
		"note":         {filter: vault.Filter{Kind: vault.KindNote}, expected: 0},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			entries, err := store.List(tc.filter)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != tc.expected {
				t.Errorf("expected %d, got %+v", tc.expected, entries)
			}
		})
	}
}

func TestIntegration_SetSettingsExistingEntry(t *testing.T) {
	store, _ := newIntegrationStore(t)
	k := vault.Key{Kind: vault.KindTOTP, Service: "github"}
	if err := store.Put(k, []byte("JBSWY3DPEHPK3PXP")); err != nil {
		t.Fatal(err)
	}
	for _, want := range []vault.Settings{
		{TOTP: totp.Params{Digits: 8}},
		{TOTP: totp.Params{Algorithm: "SHA512", Period: 60}},
		{},
	} {
		if err := store.SetSettings(k, want); err != nil {
			t.Fatal(err)
		}
		if e, err := store.Lookup(k); err != nil || e.Settings != want {
			t.Fatalf("Lookup = %+v, %v; want settings %+v", e.Settings, err, want)
		}
	}
	if got, err := store.Get(k); err != nil || string(got) != "JBSWY3DPEHPK3PXP" {
		t.Errorf("the secret after changing settings = %q, %v", got, err)
	}
}

// --- TOTP code generation parity tests ---
// These mirror the exact flow the TOTP and AWS providers use:
// store secret → retrieve from store → generate codes via totp package

func TestIntegration_TOTPProviderCodeGenFlow(t *testing.T) {
	store, _ := newIntegrationStore(t)
	totpSvc := totp.NewDefaultProvider()
	secret := []byte("JBSWY3DPEHPK3PXP")
	k := vault.Key{Kind: vault.KindTOTP, Service: "github"}

	t.Log("Store TOTP secret")
	if err := store.Put(k, secret); err != nil {
		t.Fatal(err)
	}

	// Retrieve — the provider reads the secret then makes a defensive copy
	t.Log("Retrieve and generate code")
	secretBytes, err := store.Get(k)
	if err != nil {
		t.Fatal(err)
	}

	secretCopy := make([]byte, len(secretBytes))
	copy(secretCopy, secretBytes)
	secure.SecureZeroBytes(secretBytes)
	defer secure.SecureZeroBytes(secretCopy)

	// Generate consecutive codes — this is what the TOTP provider does
	current, next, err := totpSvc.GenerateConsecutiveCodesBytes(secretCopy)
	if err != nil {
		t.Fatalf("GenerateConsecutiveCodesBytes: %v", err)
	}

	t.Logf("  Current: %s  Next: %s", current, next)

	// Validate code format
	for _, code := range []string{current, next} {
		if len(code) != 6 {
			t.Fatalf("expected 6-digit code, got %q (len=%d)", code, len(code))
		}
		for _, c := range code {
			if c < '0' || c > '9' {
				t.Fatalf("expected numeric code, got %q", code)
			}
		}
	}
}

func TestIntegration_AWSProviderCodeGenFlow(t *testing.T) {
	store, _ := newIntegrationStore(t)
	totpSvc := totp.NewDefaultProvider()
	secret := []byte("JBSWY3DPEHPK3PXP")
	device := "arn:aws:iam::123456789012:mfa/alice"

	// The entry AWS setup creates: the MFA secret with its device.
	t.Log("Store AWS MFA secret and device")
	if err := store.Save(&vault.Entry{Key: vault.AWSKey("production"), Settings: vault.Settings{AWSMFADevice: device}}, secret); err != nil {
		t.Fatal(err)
	}

	// AWS provider flow: read the device, then the secret, then generate codes
	t.Log("Read the MFA device")
	e, err := store.Lookup(vault.AWSKey("production"))
	if err != nil {
		t.Fatal(err)
	}
	gotSerial := e.Settings.AWSMFADevice
	t.Logf("  Device: %s", gotSerial)

	t.Log("Retrieve TOTP secret and generate codes")
	secretBytes, err := store.Get(vault.AWSKey("production"))
	if err != nil {
		t.Fatal(err)
	}

	secretCopy := make([]byte, len(secretBytes))
	copy(secretCopy, secretBytes)
	secure.SecureZeroBytes(secretBytes)
	defer secure.SecureZeroBytes(secretCopy)

	current, next, err := totpSvc.GenerateConsecutiveCodesBytes(secretCopy)
	if err != nil {
		t.Fatalf("GenerateConsecutiveCodesBytes: %v", err)
	}

	t.Logf("  Current: %s  Next: %s", current, next)

	// Both codes should be valid 6-digit strings
	for label, code := range map[string]string{"current": current, "next": next} {
		if len(code) != 6 {
			t.Fatalf("%s: expected 6-digit code, got %q", label, code)
		}
	}

	// Verify the complete flow produced non-empty serial and codes
	if gotSerial == "" || current == "" || next == "" {
		t.Fatal("AWS provider flow produced empty results")
	}
	t.Log("  AWS provider flow complete: serial + current + next codes")
}

func TestIntegration_TOTPSecretValidationRoundTrip(t *testing.T) {
	store, _ := newIntegrationStore(t)
	k := vault.Key{Kind: vault.KindTOTP, Service: "test-service"}

	// Validate and normalize a secret, then store it, then retrieve and generate
	t.Log("Validate, store, retrieve, generate")
	rawSecret := "jbsw y3dp ehpk 3pxp" // lowercase, spaces — needs normalization
	normalized, err := totp.ValidateAndNormalizeSecret(rawSecret)
	if err != nil {
		t.Fatalf("ValidateAndNormalizeSecret: %v", err)
	}
	t.Logf("  Normalized: %q", normalized)

	if err := store.Put(k, []byte(normalized)); err != nil {
		t.Fatal(err)
	}

	secretBytes, err := store.Get(k)
	if err != nil {
		t.Fatal(err)
	}
	defer secure.SecureZeroBytes(secretBytes)

	code, err := totp.GenerateBytes(secretBytes)
	if err != nil {
		t.Fatalf("GenerateBytes: %v", err)
	}
	t.Logf("  Generated code: %s", code)
	if len(code) != 6 {
		t.Fatalf("expected 6-digit code, got %q", code)
	}
}

func TestIntegration_QRCodeToStoreToGenerate(t *testing.T) {
	store, _ := newIntegrationStore(t)
	totpSvc := totp.NewDefaultProvider()
	k := vault.Key{Kind: vault.KindTOTP, Service: "github"}

	// Generate a QR code image with a known secret — mimics what a service would show
	t.Log("Generate QR code image")
	key, err := otplib.Generate(otplib.GenerateOpts{
		Issuer:      "GitHub",
		AccountName: "alice@example.com",
		Secret:      []byte("JBSWY3DPEHPK3PXP"),
	})
	if err != nil {
		t.Fatalf("Generate TOTP key: %v", err)
	}

	img, err := key.Image(200, 200)
	if err != nil {
		t.Fatalf("Generate QR image: %v", err)
	}

	// Decode the QR image — this is what ScanQRCode does after screencapture
	t.Log("Decode QR code from image")
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatal(err)
	}
	decodedImg, err := png.Decode(&buf)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := qrcode.DecodeQRCodeFromImage(decodedImg)
	if err != nil {
		t.Fatalf("DecodeQRCodeFromImage: %v", err)
	}
	t.Logf("  Decoded secret: %q", secret)

	if secret == "" {
		t.Fatal("expected non-empty secret from QR code")
	}

	// Validate and normalize — this is what StoreTOTPSecret does
	t.Log("Validate and normalize secret")
	normalized, err := totp.ValidateAndNormalizeSecret(secret)
	if err != nil {
		t.Fatalf("ValidateAndNormalizeSecret: %v", err)
	}
	t.Logf("  Normalized: %q", normalized)

	// Store in SQLite
	t.Log("Store in the vault")
	settings := vault.Settings{TOTP: totp.Params{Issuer: "GitHub"}}
	if err := store.Save(&vault.Entry{Key: k, Settings: settings}, []byte(normalized)); err != nil {
		t.Fatal(err)
	}

	// Retrieve and generate code
	t.Log("Retrieve and generate TOTP code")
	secretBytes, err := store.Get(k)
	if err != nil {
		t.Fatal(err)
	}
	defer secure.SecureZeroBytes(secretBytes)

	current, next, err := totpSvc.GenerateConsecutiveCodesBytes(secretBytes)
	if err != nil {
		t.Fatalf("GenerateConsecutiveCodesBytes: %v", err)
	}
	t.Logf("  Current: %s  Next: %s", current, next)

	for _, code := range []string{current, next} {
		if len(code) != 6 {
			t.Fatalf("expected 6-digit code, got %q", code)
		}
	}

	// Verify it shows up in the list with its settings
	entries, err := store.List(vault.Filter{Kind: vault.KindTOTP})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Key != k || entries[0].Settings != settings {
		t.Fatalf("List = %+v, want github with settings %+v", entries, settings)
	}
	t.Log("  Full QR → store → generate flow complete")
}

func TestIntegration_TOTPParamsNonDefault(t *testing.T) {
	store, mgr := newIntegrationStore(t)

	// Store TOTP with non-standard params: SHA256, 8 digits, 60-second period
	t.Log("Store TOTP with non-default params")
	params := totp.Params{
		Issuer:    "Acme Corp",
		Algorithm: "SHA256",
		Digits:    8,
		Period:    60,
	}
	if err := mgr.StoreTOTPSecretWithParams("acme", "admin", "JBSWY3DPEHPK3PXP", params); err != nil {
		t.Fatal(err)
	}

	// Retrieve params
	t.Log("Retrieve TOTP params")
	e, err := store.Lookup(vault.Key{Kind: vault.KindTOTP, Service: "acme", Username: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	got := e.Settings.TOTP
	t.Logf("  Issuer: %s, Algorithm: %s, Digits: %d, Period: %d",
		got.Issuer, got.Algorithm, got.Digits, got.Period)

	if got.Issuer != "Acme Corp" {
		t.Fatalf("expected issuer 'Acme Corp', got %q", got.Issuer)
	}
	if got.Algorithm != "SHA256" {
		t.Fatalf("expected algorithm SHA256, got %q", got.Algorithm)
	}
	if got.Digits != 8 {
		t.Fatalf("expected 8 digits, got %d", got.Digits)
	}
	if got.Period != 60 {
		t.Fatalf("expected 60s period, got %d", got.Period)
	}

	// Generate code with non-default params
	t.Log("Generate code with non-default params")
	code, err := mgr.GenerateTOTPCode("acme", "admin")
	if err != nil {
		t.Fatalf("GenerateTOTPCode: %v", err)
	}
	t.Logf("  Code: %s (len=%d)", code, len(code))
	if len(code) != 8 {
		t.Fatalf("expected 8-digit code, got %q (len=%d)", code, len(code))
	}
}

func TestIntegration_TOTPParamsDefault(t *testing.T) {
	store, mgr := newIntegrationStore(t)

	// Store with default params — should generate 6-digit codes
	t.Log("Store TOTP with default params")
	if err := mgr.StoreTOTPSecret("github", "alice", "JBSWY3DPEHPK3PXP"); err != nil {
		t.Fatal(err)
	}

	// Params should be zero/default
	e, err := store.Lookup(vault.Key{Kind: vault.KindTOTP, Service: "github", Username: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	if params := e.Settings.TOTP; !params.IsDefault() {
		t.Fatalf("expected default params, got %+v", params)
	}
	t.Log("  Params: default")

	// Generate standard 6-digit code
	code, err := mgr.GenerateTOTPCode("github", "alice")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("  Code: %s (len=%d)", code, len(code))
	if len(code) != 6 {
		t.Fatalf("expected 6-digit code, got %q", code)
	}
}

func TestIntegration_QRCodeFullInfo(t *testing.T) {
	// Test ExtractTOTPFullInfo with non-standard params
	t.Log("Parse otpauth URI with non-standard params")
	uri := "otpauth://totp/Acme:admin@acme.com?secret=JBSWY3DPEHPK3PXP&issuer=Acme&algorithm=SHA256&digits=8&period=60"
	info, err := qrcode.ExtractTOTPFullInfo(uri)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("  Secret: %s, Issuer: %s, Account: %s", info.Secret, info.Issuer, info.Account)
	t.Logf("  Algorithm: %s, Digits: %d, Period: %d", info.Algorithm, info.Digits, info.Period)

	if info.Secret != "JBSWY3DPEHPK3PXP" {
		t.Fatalf("expected secret JBSWY3DPEHPK3PXP, got %q", info.Secret)
	}
	if info.Issuer != "Acme" {
		t.Fatalf("expected issuer Acme, got %q", info.Issuer)
	}
	if info.Account != "admin@acme.com" {
		t.Fatalf("expected account admin@acme.com, got %q", info.Account)
	}
	if info.Algorithm != "SHA256" {
		t.Fatalf("expected SHA256, got %q", info.Algorithm)
	}
	if info.Digits != 8 {
		t.Fatalf("expected 8, got %d", info.Digits)
	}
	if info.Period != 60 {
		t.Fatalf("expected 60, got %d", info.Period)
	}

	// Standard URI should have zero defaults
	t.Log("Parse standard otpauth URI")
	stdURI := "otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP&issuer=GitHub"
	stdInfo, err := qrcode.ExtractTOTPFullInfo(stdURI)
	if err != nil {
		t.Fatal(err)
	}
	if stdInfo.Algorithm != "" || stdInfo.Digits != 0 || stdInfo.Period != 0 {
		t.Fatalf("expected zero defaults for standard URI, got algorithm=%q digits=%d period=%d",
			stdInfo.Algorithm, stdInfo.Digits, stdInfo.Period)
	}
	t.Log("  Standard URI: defaults as expected")
}

func TestIntegration_ExportImportJSON(t *testing.T) {
	_, mgr := newIntegrationStore(t)

	if err := mgr.StorePasswordString("github", "alice", "gh-secret", password.EntryTypePassword); err != nil {
		t.Fatal(err)
	}
	if err := mgr.StorePasswordString("stripe", "admin", "sk_live_123", password.EntryTypeAPIKey); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	count, err := mgr.Export(&buf, password.ExportOptions{Format: password.FormatJSON})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Exported %d entries (%d bytes)", count, buf.Len())
	if count != 2 {
		t.Fatalf("expected 2, got %d", count)
	}

	var exported []password.ExportEntry
	if err := json.Unmarshal(buf.Bytes(), &exported); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(exported) != 2 {
		t.Fatalf("expected 2 entries in JSON, got %d", len(exported))
	}

	_, mgr2 := newIntegrationStore(t)
	result, err := mgr2.Import(&buf, password.ImportOptions{Format: password.FormatJSON})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Imported %d, skipped %d, errors %d", result.Imported, result.Skipped, len(result.Errors))
	if result.Imported != 2 {
		t.Fatalf("expected 2 imported, got %d", result.Imported)
	}

	pw, err := mgr2.GetPasswordString("github", "alice", password.EntryTypePassword)
	if err != nil {
		t.Fatal(err)
	}
	if pw != "gh-secret" {
		t.Fatalf("expected 'gh-secret', got %q", pw)
	}
}

func TestIntegration_ExportImportCSV(t *testing.T) {
	_, mgr := newIntegrationStore(t)

	if err := mgr.StorePasswordString("github", "alice", "gh-secret", password.EntryTypePassword); err != nil {
		t.Fatal(err)
	}
	if err := mgr.StorePasswordString("stripe", "", "sk_live_123", password.EntryTypeAPIKey); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	count, err := mgr.Export(&buf, password.ExportOptions{Format: password.FormatCSV})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Exported %d entries as CSV", count)

	_, mgr2 := newIntegrationStore(t)
	result, err := mgr2.Import(bytes.NewReader(buf.Bytes()), password.ImportOptions{Format: password.FormatCSV})
	if err != nil {
		t.Fatal(err)
	}
	if result.Imported != 2 {
		t.Fatalf("expected 2 imported, got %d", result.Imported)
	}

	pw, err := mgr2.GetPasswordString("github", "alice", password.EntryTypePassword)
	if err != nil {
		t.Fatal(err)
	}
	if pw != "gh-secret" {
		t.Fatalf("expected 'gh-secret', got %q", pw)
	}
}

func TestIntegration_ImportConflictSkip(t *testing.T) {
	_, mgr := newIntegrationStore(t)

	if err := mgr.StorePasswordString("github", "alice", "original", password.EntryTypePassword); err != nil {
		t.Fatal(err)
	}

	data := `[{"service":"github","username":"alice","type":"password","secret":"new-value"}]`
	result, err := mgr.Import(strings.NewReader(data), password.ImportOptions{
		Format:     password.FormatJSON,
		OnConflict: password.ConflictSkip,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Skipped != 1 {
		t.Fatalf("expected 1 skipped, got %d", result.Skipped)
	}

	pw, err := mgr.GetPasswordString("github", "alice", password.EntryTypePassword)
	if err != nil {
		t.Fatal(err)
	}
	if pw != "original" {
		t.Fatalf("expected 'original' preserved, got %q", pw)
	}
}

func TestIntegration_ImportConflictOverwrite(t *testing.T) {
	_, mgr := newIntegrationStore(t)

	if err := mgr.StorePasswordString("github", "alice", "original", password.EntryTypePassword); err != nil {
		t.Fatal(err)
	}

	data := `[{"service":"github","username":"alice","type":"password","secret":"updated"}]`
	result, err := mgr.Import(strings.NewReader(data), password.ImportOptions{
		Format:     password.FormatJSON,
		OnConflict: password.ConflictOverwrite,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Imported != 1 {
		t.Fatalf("expected 1 imported, got %d", result.Imported)
	}

	pw, err := mgr.GetPasswordString("github", "alice", password.EntryTypePassword)
	if err != nil {
		t.Fatal(err)
	}
	if pw != "updated" {
		t.Fatalf("expected 'updated', got %q", pw)
	}
}

func TestIntegration_ExportWithFilter(t *testing.T) {
	_, mgr := newIntegrationStore(t)

	if err := mgr.StorePasswordString("github", "alice", "pw1", password.EntryTypePassword); err != nil {
		t.Fatal(err)
	}
	if err := mgr.StorePasswordString("stripe", "admin", "key1", password.EntryTypeAPIKey); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	count, err := mgr.Export(&buf, password.ExportOptions{
		Format:    password.FormatJSON,
		EntryType: password.EntryTypeAPIKey,
	})
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("expected 1 api_key exported, got %d", count)
	}

	var exported []password.ExportEntry
	if err := json.Unmarshal(buf.Bytes(), &exported); err != nil {
		t.Fatal(err)
	}
	if exported[0].Service != "stripe" {
		t.Fatalf("expected stripe, got %q", exported[0].Service)
	}
}

func openTestdata(t *testing.T, name string) *os.File {
	t.Helper()
	f, err := os.Open(name)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := f.Close(); err != nil {
			t.Errorf("close %s: %v", name, err)
		}
	})
	return f
}

func TestIntegration_ImportFromJSONFile(t *testing.T) {
	_, mgr := newIntegrationStore(t)

	f := openTestdata(t, "testdata/import_valid.json")
	result, err := mgr.Import(f, password.ImportOptions{Format: password.FormatJSON})
	if err != nil {
		t.Fatal(err)
	}
	if result.Imported != 4 {
		t.Fatalf("expected 4 imported, got %d", result.Imported)
	}

	pw, err := mgr.GetPasswordString("github", "alice", password.EntryTypePassword)
	if err != nil {
		t.Fatal(err)
	}
	if pw != "gh-pat-abc123def456" {
		t.Fatalf("expected github password, got %q", pw)
	}

	note, err := mgr.GetPasswordString("personal", "recovery-codes", password.EntryTypeNote)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(note, "abc-123-def") {
		t.Fatalf("expected recovery codes in note, got %q", note)
	}
	t.Logf("Imported 4 entries from JSON fixture: password, api_key, totp, secure_note")
}

func TestIntegration_ImportFromCSVFile(t *testing.T) {
	_, mgr := newIntegrationStore(t)

	f := openTestdata(t, "testdata/import_valid.csv")
	result, err := mgr.Import(f, password.ImportOptions{Format: password.FormatCSV})
	if err != nil {
		t.Fatal(err)
	}
	if result.Imported != 3 {
		t.Fatalf("expected 3 imported, got %d", result.Imported)
	}

	pw, err := mgr.GetPasswordString("stripe", "admin", password.EntryTypeAPIKey)
	if err != nil {
		t.Fatal(err)
	}
	if pw != "fake-stripe-key-abc123def456" {
		t.Fatalf("expected stripe key, got %q", pw)
	}
}

func TestIntegration_ImportCSVReorderedColumns(t *testing.T) {
	_, mgr := newIntegrationStore(t)

	f := openTestdata(t, "testdata/import_reordered_columns.csv")
	result, err := mgr.Import(f, password.ImportOptions{Format: password.FormatCSV})
	if err != nil {
		t.Fatal(err)
	}
	if result.Imported != 2 {
		t.Fatalf("expected 2 imported, got %d", result.Imported)
	}

	pw, err := mgr.GetPasswordString("gitlab", "bob", password.EntryTypePassword)
	if err != nil {
		t.Fatal(err)
	}
	if pw != "my-secret" {
		t.Fatalf("expected 'my-secret', got %q", pw)
	}
}

func TestIntegration_ImportBadJSON(t *testing.T) {
	_, mgr := newIntegrationStore(t)

	f := openTestdata(t, "testdata/import_bad.json")
	_, err := mgr.Import(f, password.ImportOptions{Format: password.FormatJSON})
	if err == nil {
		t.Fatal("expected error for bad JSON")
	}
}

func TestIntegration_ImportCSVMissingColumn(t *testing.T) {
	_, mgr := newIntegrationStore(t)

	f := openTestdata(t, "testdata/import_missing_column.csv")
	_, err := mgr.Import(f, password.ImportOptions{Format: password.FormatCSV})
	if err == nil {
		t.Fatal("expected error for missing 'secret' column")
	}
}

func TestIntegration_ImportDuplicatesDefaultError(t *testing.T) {
	_, mgr := newIntegrationStore(t)

	f := openTestdata(t, "testdata/import_duplicates.json")
	result, err := mgr.Import(f, password.ImportOptions{Format: password.FormatJSON})
	if err != nil {
		t.Fatal(err)
	}

	if result.Imported != 1 {
		t.Fatalf("expected 1 imported (first entry), got %d", result.Imported)
	}
	if len(result.Errors) != 1 {
		t.Fatalf("expected 1 error (duplicate), got %d", len(result.Errors))
	}

	pw, err := mgr.GetPasswordString("github", "alice", password.EntryTypePassword)
	if err != nil {
		t.Fatal(err)
	}
	if pw != "first-password" {
		t.Fatalf("expected first-password preserved, got %q", pw)
	}
}

func TestIntegration_ImportInvalidEntryType(t *testing.T) {
	_, mgr := newIntegrationStore(t)

	data := `[{"service":"github","username":"alice","type":"bogus","secret":"pw1"}]`
	result, err := mgr.Import(strings.NewReader(data), password.ImportOptions{Format: password.FormatJSON})
	if err != nil {
		t.Fatal(err)
	}
	if result.Imported != 0 {
		t.Fatalf("expected 0 imported, got %d", result.Imported)
	}
	if len(result.Errors) != 1 {
		t.Fatalf("expected 1 error, got %d", len(result.Errors))
	}
	if !strings.Contains(result.Errors[0], "invalid entry type") {
		t.Fatalf("expected 'invalid entry type' error, got %q", result.Errors[0])
	}
}

func TestIntegration_ImportEmptyFields(t *testing.T) {
	_, mgr := newIntegrationStore(t)

	data := `[
		{"service":"","username":"alice","type":"password","secret":"pw1"},
		{"service":"github","username":"alice","type":"password","secret":""}
	]`
	result, err := mgr.Import(strings.NewReader(data), password.ImportOptions{Format: password.FormatJSON})
	if err != nil {
		t.Fatal(err)
	}
	if result.Imported != 0 {
		t.Fatalf("expected 0 imported, got %d", result.Imported)
	}
	if len(result.Errors) != 2 {
		t.Fatalf("expected 2 errors, got %d: %v", len(result.Errors), result.Errors)
	}
}

func TestIntegration_ImportEmptyArray(t *testing.T) {
	_, mgr := newIntegrationStore(t)

	result, err := mgr.Import(strings.NewReader("[]"), password.ImportOptions{Format: password.FormatJSON})
	if err != nil {
		t.Fatal(err)
	}
	if result.Imported != 0 {
		t.Fatalf("expected 0 imported, got %d", result.Imported)
	}
	if len(result.Errors) != 0 {
		t.Fatalf("expected 0 errors, got %d", len(result.Errors))
	}
}

func TestIntegration_ExportThenImportRoundTrip(t *testing.T) {
	_, mgr1 := newIntegrationStore(t)

	if err := mgr1.StorePasswordString("github", "alice", "pw1", password.EntryTypePassword); err != nil {
		t.Fatal(err)
	}
	if err := mgr1.StorePasswordString("stripe", "admin", "key1", password.EntryTypeAPIKey); err != nil {
		t.Fatal(err)
	}
	if err := mgr1.StorePasswordString("notes", "backup", "my secure note\nwith newlines", password.EntryTypeNote); err != nil {
		t.Fatal(err)
	}

	for _, format := range []password.ExportFormat{password.FormatJSON, password.FormatCSV} {
		t.Run(string(format), func(t *testing.T) {
			var buf bytes.Buffer
			count, err := mgr1.Export(&buf, password.ExportOptions{Format: format})
			if err != nil {
				t.Fatal(err)
			}
			if count != 3 {
				t.Fatalf("expected 3 exported, got %d", count)
			}

			_, mgr2 := newIntegrationStore(t)
			result, err := mgr2.Import(bytes.NewReader(buf.Bytes()), password.ImportOptions{Format: format})
			if err != nil {
				t.Fatal(err)
			}
			if result.Imported != 3 {
				t.Fatalf("expected 3 imported, got %d (errors: %v)", result.Imported, result.Errors)
			}

			entries, err := mgr2.ListEntries()
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 3 {
				t.Fatalf("expected 3 entries after import, got %d", len(entries))
			}
		})
	}
}

// failingWriter errors once more than budget bytes have been written.
type failingWriter struct {
	budget int
	failed bool
}

func (f *failingWriter) Write(p []byte) (int, error) {
	if f.failed {
		return 0, fmt.Errorf("writer closed")
	}
	if len(p) <= f.budget {
		f.budget -= len(p)
		return len(p), nil
	}
	n := f.budget
	f.budget = 0
	f.failed = true
	return n, fmt.Errorf("write budget exhausted")
}

func TestIntegration_ExportJSONStreamsEntries(t *testing.T) {
	_, mgr := newIntegrationStore(t)
	const total = 5
	for _, svc := range []string{"a", "b", "c", "d", "e"} {
		if err := mgr.StorePasswordString(svc, "alice", "secret-"+svc, password.EntryTypePassword); err != nil {
			t.Fatal(err)
		}
	}

	// A buffered-then-write implementation returns count=total regardless
	// of writer success; streaming must return a strictly smaller count
	// when the writer fails mid-way.
	fw := &failingWriter{budget: 200}
	count, err := mgr.Export(fw, password.ExportOptions{Format: password.FormatJSON})
	if err == nil {
		t.Fatal("expected error from truncated writer, got nil")
	}
	if count >= total {
		t.Fatalf("non-streaming behavior: got count=%d (want < %d) after write failure", count, total)
	}
}

func TestIntegration_ExportImportPreservesTimestamps(t *testing.T) {
	// Audit history must survive a round-trip — otherwise sort-by-created
	// and the audit log silently lose meaning every time a user restores
	// from backup.
	store1, mgr1 := newIntegrationStore(t)

	historicCreated := time.Date(2025, 3, 10, 12, 0, 0, 0, time.UTC)
	historicUpdated := time.Date(2025, 9, 15, 18, 30, 0, 0, time.UTC)

	if err := store1.Save(&vault.Entry{Kind: vault.KindPassword, Service: "github", Username: "alice", CreatedAt: historicCreated, UpdatedAt: historicUpdated}, []byte("pw1")); err != nil {
		t.Fatal(err)
	}

	for _, format := range []password.ExportFormat{password.FormatJSON, password.FormatCSV} {
		t.Run(string(format), func(t *testing.T) {
			var buf bytes.Buffer
			if _, err := mgr1.Export(&buf, password.ExportOptions{Format: format}); err != nil {
				t.Fatal(err)
			}

			store2, mgr2 := newIntegrationStore(t)
			result, err := mgr2.Import(bytes.NewReader(buf.Bytes()), password.ImportOptions{Format: format})
			if err != nil {
				t.Fatal(err)
			}
			if result.Imported != 1 {
				t.Fatalf("expected 1 imported, got %d (errors: %v)", result.Imported, result.Errors)
			}

			entries, err := store2.List(vault.Filter{})
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 1 {
				t.Fatalf("expected 1 entry, got %d", len(entries))
			}
			if !entries[0].CreatedAt.Equal(historicCreated) {
				t.Errorf("CreatedAt after round-trip = %v, want %v", entries[0].CreatedAt, historicCreated)
			}
			if !entries[0].UpdatedAt.Equal(historicUpdated) {
				t.Errorf("UpdatedAt after round-trip = %v, want %v", entries[0].UpdatedAt, historicUpdated)
			}
		})
	}
}
