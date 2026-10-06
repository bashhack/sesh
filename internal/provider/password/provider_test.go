package password

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"strings"
	"testing"

	"github.com/bashhack/sesh/internal/password"
	"github.com/bashhack/sesh/internal/qrcode"
	"github.com/bashhack/sesh/internal/testutil"
	"github.com/bashhack/sesh/internal/totp"
	"github.com/bashhack/sesh/internal/vault"
)

func TestName(t *testing.T) {
	p := NewProvider(vault.NewMemStore())
	if p.Name() != "password" {
		t.Errorf("expected name 'password', got %q", p.Name())
	}
}

func TestValidateRequest(t *testing.T) {
	tests := map[string]struct {
		action  string
		service string
		query   string
		wantErr bool
	}{
		"store without service": {
			action: "store", service: "", wantErr: true,
		},
		"store with service": {
			action: "store", service: "github", wantErr: false,
		},
		"get without service": {
			action: "get", service: "", wantErr: true,
		},
		"get with service": {
			action: "get", service: "github", wantErr: false,
		},
		"search without query": {
			action: "search", query: "", wantErr: true,
		},
		"search with query": {
			action: "search", query: "git", wantErr: false,
		},
		"totp-store without service": {
			action: "totp-store", service: "", wantErr: true,
		},
		"totp-generate with service": {
			action: "totp-generate", service: "github", wantErr: false,
		},
		"unknown action": {
			action: "bogus", wantErr: true,
		},
		"empty action": {
			action: "", wantErr: false,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			p := &Provider{
				action:  tc.action,
				service: tc.service,
				query:   tc.query,
			}
			err := p.ValidateRequest()
			if (err != nil) != tc.wantErr {
				t.Errorf("ValidateRequest() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestValidateRequest_EntryType(t *testing.T) {
	tests := map[string]struct {
		action, entryType, username string
		wantSub                     string // empty: no error
	}{
		"password":                   {action: "store", entryType: "password"},
		"api key":                    {action: "store", entryType: "api_key"},
		"totp":                       {action: "store", entryType: "totp"},
		"note":                       {action: "store", entryType: "secure_note"},
		"none":                       {action: "store"},
		"misspelled":                 {action: "store", entryType: "apikey", wantSub: `unknown --entry-type "apikey": use password, api_key, totp, or secure_note`},
		"misspelled on get":          {action: "get", entryType: "note", wantSub: `unknown --entry-type "note"`},
		"misspelled search":          {action: "search", entryType: "pw", wantSub: `unknown --entry-type "pw"`},
		"misspelled export":          {action: "export", entryType: "keys", wantSub: `unknown --entry-type "keys"`},
		"generate a key":             {action: "generate", entryType: "api_key"},
		"generate a TOTP":            {action: "generate", entryType: "totp", wantSub: "sesh can't generate a TOTP secret: the service gives you one. Store it with: sesh --service password --action totp-store --service-name github"},
		"generate a TOTP for a user": {action: "generate", entryType: "totp", username: "alice", wantSub: "--action totp-store --service-name github --username alice"},
		"generate misspelled":        {action: "generate", entryType: "totpp", wantSub: `unknown --entry-type "totpp"`},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			p := &Provider{action: tc.action, service: "github", username: tc.username, query: "git", entryType: tc.entryType, format: "json"}
			err := p.ValidateRequest()
			switch {
			case tc.wantSub == "" && err != nil:
				t.Errorf("ValidateRequest() = %v, want no error", err)
			case tc.wantSub != "" && (err == nil || !strings.Contains(err.Error(), tc.wantSub)):
				t.Errorf("ValidateRequest() = %v, want it to contain %q", err, tc.wantSub)
			}
		})
	}
}

func TestListEntries_RefusesAnUnknownEntryType(t *testing.T) {
	p, _ := newTestProvider(vault.NewMemStore())
	p.entryType = "apikey"
	if _, err := p.ListEntries(); err == nil || !strings.Contains(err.Error(), `unknown --entry-type "apikey"`) {
		t.Errorf("ListEntries() = %v, want an unknown --entry-type error", err)
	}
}

func TestListEntriesWithFilters(t *testing.T) {
	store := seeded(t, map[string]string{"password/github/user1": "x", "api_key/stripe": "x", "password/gitlab/user2": "x"})
	tests := map[string]struct {
		entryType string
		sortBy    string
		limit     int
		offset    int
		expected  int
	}{
		"no filters":      {entryType: "", sortBy: "service", expected: 3},
		"filter api_key":  {entryType: "api_key", sortBy: "service", expected: 1},
		"filter password": {entryType: "password", sortBy: "service", expected: 2},
		"with limit":      {entryType: "", sortBy: "service", limit: 2, expected: 2},
		"with offset":     {entryType: "", sortBy: "service", offset: 2, expected: 1},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			p := &Provider{store: store, entryType: tc.entryType, sortBy: tc.sortBy, limit: tc.limit, offset: tc.offset}
			entries, err := p.ListEntries()
			if err != nil {
				t.Fatalf("ListEntries: %v", err)
			}
			if len(entries) != tc.expected {
				t.Errorf("expected %d entries, got %d", tc.expected, len(entries))
			}
		})
	}
	entries, err := (&Provider{store: store}).ListEntries()
	if err != nil {
		t.Fatal(err)
	}
	// Listed by service name; the ID is what --delete takes.
	if e := entries[0]; e.ID != "password/github/user1" || e.Name != "github (user1)" || e.Description != "[password]" {
		t.Errorf("first entry = %+v, want ID password/github/user1, name github (user1), [password]", e)
	}
}

func TestDeleteEntryWithForce(t *testing.T) {
	store := seeded(t, map[string]string{"password/github/user1": "x"})
	p := &Provider{store: store, force: true}
	if err := p.DeleteEntry("password/github/user1"); err != nil {
		t.Fatalf("DeleteEntry: %v", err)
	}
	if _, err := store.Lookup(vault.Key{Kind: vault.KindPassword, Service: "github", Username: "user1"}); !errors.Is(err, vault.ErrNotFound) {
		t.Errorf("the entry is still there: %v", err)
	}
}

func TestDescription(t *testing.T) {
	p := NewProvider(vault.NewMemStore())
	if p.Description() == "" {
		t.Error("Description should not be empty")
	}
}

func TestGetSetupHandler(t *testing.T) {
	// Password provider has no interactive setup wizard — ensure it
	// returns nil so the setup dispatcher doesn't try to invoke one.
	if h := NewProvider(vault.NewMemStore()).GetSetupHandler(); h != nil {
		t.Errorf("GetSetupHandler() = %v, want nil", h)
	}
}

func TestSuppressActionFraming(t *testing.T) {
	if !NewProvider(vault.NewMemStore()).SuppressActionFraming() {
		t.Error("SuppressActionFraming() = false, want true")
	}
}

func TestSetupFlags(t *testing.T) {
	p := NewProvider(vault.NewMemStore())
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	if err := p.SetupFlags(fs); err != nil {
		t.Fatalf("SetupFlags() unexpected error: %v", err)
	}
	if err := fs.Parse([]string{"--action", "store", "--show", "--length", "32"}); err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if p.action != "store" {
		t.Errorf("action = %q, want store", p.action)
	}
	if !p.show {
		t.Error("show flag should have been set")
	}
	if p.pwLength != 32 {
		t.Errorf("pwLength = %d, want 32", p.pwLength)
	}
}

func TestEffectiveEntryType(t *testing.T) {
	tests := map[string]password.EntryType{
		"":            password.EntryTypePassword,
		"password":    password.EntryTypePassword,
		"api_key":     password.EntryTypeAPIKey,
		"totp":        password.EntryTypeTOTP,
		"secure_note": password.EntryTypeNote,
	}
	for entryType, want := range tests {
		t.Run("type="+entryType, func(t *testing.T) {
			p := &Provider{store: vault.NewMemStore(), entryType: entryType}
			if got := p.effectiveEntryType(); got != want {
				t.Errorf("effectiveEntryType(%q) = %v, want %v", entryType, got, want)
			}
		})
	}
}

// TestDeleteEntry_InvalidID: a malformed ID is refused before asking.
func TestDeleteEntry_InvalidID(t *testing.T) {
	p := &Provider{store: vault.NewMemStore(), stdin: strings.NewReader("")}
	err := p.DeleteEntry("not-a-valid-id")
	if err == nil || !strings.Contains(err.Error(), "want kind/service") {
		t.Fatalf("err = %v, want the entry ID refused", err)
	}
}

// stubReadPassword overrides the package-level readPassword seam.
func stubReadPassword(t *testing.T, value string) {
	t.Helper()
	orig := readPassword
	readPassword = func() ([]byte, error) {
		return []byte(value), nil
	}
	t.Cleanup(func() { readPassword = orig })
}

func stubStdinIsTerminal(t *testing.T, isTTY bool) {
	t.Helper()
	orig := stdinIsTerminal
	stdinIsTerminal = func() bool { return isTTY }
	t.Cleanup(func() { stdinIsTerminal = orig })
}

func stubScanQRCodeFull(t *testing.T, info qrcode.TOTPInfo, err error) {
	t.Helper()
	orig := scanQRCodeFull
	scanQRCodeFull = func() (qrcode.TOTPInfo, error) {
		if err != nil {
			return qrcode.TOTPInfo{}, err
		}
		return info, nil
	}
	t.Cleanup(func() { scanQRCodeFull = orig })
}

// newTestProvider builds a Provider with a buffered stdout and an empty
// stdin. Prompts still go to the real os.Stderr — tests don't assert on
// prompt text, so there's no need to capture it.
func newTestProvider(store vault.Store) (*Provider, *bytes.Buffer) {
	p := NewProvider(store)
	var stdout bytes.Buffer
	p.stdout = &stdout
	p.stdin = strings.NewReader("")
	return p, &stdout
}

// seeded is a store holding the entries named (kind/service[/username])
// with the given secrets.
func seeded(t *testing.T, entries map[string]string) *vault.MemStore {
	t.Helper()
	store := vault.NewMemStore()
	for id, secret := range entries {
		k, err := vault.ParseKey(id)
		if err != nil {
			t.Fatal(err)
		}
		if err := store.Put(k, []byte(secret)); err != nil {
			t.Fatal(err)
		}
	}
	return store
}

// stored is the secret store holds for the entry id names, or "" if none.
func stored(t *testing.T, store vault.Store, id string) string {
	t.Helper()
	k, err := vault.ParseKey(id)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := store.Get(k)
	if err != nil {
		return ""
	}
	return string(secret)
}

func TestStorePassword_HappyPath(t *testing.T) {
	stubReadPassword(t, "s3cret")
	store := vault.NewMemStore()
	p, _ := newTestProvider(store)
	p.action, p.service, p.username, p.force = "store", "github", "alice", true

	creds, err := p.GetCredentials()
	if err != nil {
		t.Fatalf("GetCredentials: %v", err)
	}
	if got := stored(t, store, "password/github/alice"); got != "s3cret" {
		t.Errorf("stored secret = %q, want s3cret", got)
	}
	if !strings.Contains(creds.DisplayInfo, "Stored password for github") {
		t.Errorf("DisplayInfo = %q, want contains 'Stored password for github'", creds.DisplayInfo)
	}
}

func TestStorePassword_OverwriteRefusedOnPipedStdin(t *testing.T) {
	stubStdinIsTerminal(t, false)

	p, _ := newTestProvider(seeded(t, map[string]string{"password/github/alice": "old"}))
	p.action = "store"
	p.service = "github"
	p.username = "alice"

	_, err := p.GetCredentials()
	if err == nil {
		t.Fatal("expected error when entry exists on piped stdin, got nil")
	}
	if !strings.Contains(err.Error(), "--force to overwrite") {
		t.Errorf("error = %v, want to mention --force", err)
	}
}

func TestStorePassword_NoteFromPipedStdin(t *testing.T) {
	stubStdinIsTerminal(t, false)
	store := vault.NewMemStore()
	p, _ := newTestProvider(store)
	p.action, p.service, p.entryType, p.force = "store", "diary", "secure_note", true
	p.stdin = strings.NewReader("line one\nline two\n")

	if _, err := p.GetCredentials(); err != nil {
		t.Fatalf("GetCredentials: %v", err)
	}
	if got := stored(t, store, "secure_note/diary"); got != "line one\nline two\n" {
		t.Errorf("stored note = %q, want multiline body", got)
	}
}

func TestGeneratePassword_HappyPathClipboardMode(t *testing.T) {
	mock := vault.NewMemStore()

	p, _ := newTestProvider(mock)
	p.action = "generate"
	p.service = "github"
	p.pwLength = 24

	creds, err := p.GetCredentials()
	if err != nil {
		t.Fatalf("GetCredentials: %v", err)
	}
	if len(creds.CopyValue) != 24 {
		t.Errorf("CopyValue length = %d, want 24", len(creds.CopyValue))
	}
	if !strings.Contains(creds.DisplayInfo, "--show") {
		t.Errorf("DisplayInfo should hint at --show/--clip, got %q", creds.DisplayInfo)
	}
}

func TestGeneratePassword_ShowEchoesPassword(t *testing.T) {
	mock := vault.NewMemStore()

	p, stdout := newTestProvider(mock)
	p.action = "generate"
	p.service = "github"
	p.pwLength = 24
	p.show = true

	creds, err := p.GetCredentials()
	if err != nil {
		t.Fatalf("GetCredentials: %v", err)
	}
	if creds.CopyValue != "" {
		t.Errorf("CopyValue = %q, want empty when --show is set", creds.CopyValue)
	}
	if creds.DisplayInfo != "✅ Generated and stored password for github" {
		t.Errorf("DisplayInfo = %q, want only the status line", creds.DisplayInfo)
	}
	if pw := strings.TrimSuffix(stdout.String(), "\n"); len(pw) != 24 || strings.Contains(pw, "\n") {
		t.Errorf("stdout = %q, want the 24-character password on one line", stdout.String())
	}
}

func TestGeneratePassword_JSONFormat(t *testing.T) {
	mock := vault.NewMemStore()

	p, stdout := newTestProvider(mock)
	p.action = "generate"
	p.service = "github"
	p.username = "alice"
	p.pwLength = 16
	p.format = "json"

	creds, err := p.GetCredentials()
	if err != nil {
		t.Fatalf("GetCredentials: %v", err)
	}
	if creds.DisplayInfo != "" {
		t.Errorf("DisplayInfo = %q, want nothing on stderr", creds.DisplayInfo)
	}
	var payload struct {
		Service  string `json:"service"`
		Username string `json:"username"`
		Type     string `json:"type"`
		Password string `json:"password"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatalf("stdout not JSON: %v (raw %q)", err, stdout.String())
	}
	if payload.Service != "github" || payload.Username != "alice" || payload.Type != "password" {
		t.Errorf("JSON header mismatch: %+v", payload)
	}
	if len(payload.Password) != 16 {
		t.Errorf("password length = %d, want 16", len(payload.Password))
	}
}

func TestGetPassword_ShowReturnsPlainSecret(t *testing.T) {
	mock := seeded(t, map[string]string{"password/github": "s3cret"})

	p, stdout := newTestProvider(mock)
	p.action = "get"
	p.service = "github"
	p.show = true

	creds, err := p.GetCredentials()
	if err != nil {
		t.Fatalf("GetCredentials: %v", err)
	}
	if stdout.String() != "s3cret\n" {
		t.Errorf("stdout = %q, want the secret and a newline", stdout.String())
	}
	if creds.DisplayInfo != "" {
		t.Errorf("DisplayInfo = %q, want nothing on stderr", creds.DisplayInfo)
	}
	if creds.CopyValue != "" {
		t.Errorf("CopyValue should be empty in --show mode, got %q", creds.CopyValue)
	}
}

func TestGetPassword_DefaultUsesClipboardPayload(t *testing.T) {
	mock := seeded(t, map[string]string{"password/github": "s3cret"})

	p, _ := newTestProvider(mock)
	p.action = "get"
	p.service = "github"

	creds, err := p.GetCredentials()
	if err != nil {
		t.Fatalf("GetCredentials: %v", err)
	}
	if creds.CopyValue != "s3cret" {
		t.Errorf("CopyValue = %q, want s3cret", creds.CopyValue)
	}
	if !strings.Contains(creds.DisplayInfo, "--show") {
		t.Errorf("DisplayInfo should hint --show, got %q", creds.DisplayInfo)
	}
}

func TestGetPassword_JSONFormat(t *testing.T) {
	mock := seeded(t, map[string]string{"password/github": "s3cret"})

	p, stdout := newTestProvider(mock)
	p.action = "get"
	p.service = "github"
	p.format = "json"

	creds, err := p.GetCredentials()
	if err != nil {
		t.Fatalf("GetCredentials: %v", err)
	}
	if creds.DisplayInfo != "" {
		t.Errorf("DisplayInfo = %q, want nothing on stderr", creds.DisplayInfo)
	}
	var payload struct {
		Password string `json:"password"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatalf("stdout not JSON: %v (raw %q)", err, stdout.String())
	}
	if payload.Password != "s3cret" {
		t.Errorf("json.password = %q, want s3cret", payload.Password)
	}
}

func TestDeleteEntry_CancelsOnNo(t *testing.T) {
	store := seeded(t, map[string]string{"password/github/user1": "x"})
	p, _ := newTestProvider(store)
	p.stdin = strings.NewReader("n\n")

	err := p.DeleteEntry("password/github/user1")
	if err == nil || !strings.Contains(err.Error(), "delete cancelled") {
		t.Errorf("expected delete-cancelled error, got %v", err)
	}
	if stored(t, store, "password/github/user1") == "" {
		t.Error("the entry was deleted though the answer was n")
	}
}

func TestDeleteEntry_ConfirmsOnYes(t *testing.T) {
	store := seeded(t, map[string]string{"password/github/user1": "x"})
	p, _ := newTestProvider(store)
	p.stdin = strings.NewReader("y\n")

	if err := p.DeleteEntry("password/github/user1"); err != nil {
		t.Fatalf("DeleteEntry: %v", err)
	}
	if stored(t, store, "password/github/user1") != "" {
		t.Error("the entry wasn't deleted though the answer was y")
	}
}

func TestStoreTOTP_QRPath(t *testing.T) {
	stubScanQRCodeFull(t, qrcode.TOTPInfo{
		Secret:    "JBSWY3DPEHPK3PXP",
		Issuer:    "GitHub",
		Account:   "alice@example.com",
		Algorithm: "SHA256",
		Digits:    8,
		Period:    60,
	}, nil)
	store := vault.NewMemStore()
	p, _ := newTestProvider(store)
	p.action = "totp-store"
	p.service = "github"
	p.stdin = strings.NewReader("2\n")

	creds, err := p.GetCredentials()
	if err != nil {
		t.Fatalf("GetCredentials: %v", err)
	}
	if p.username != "alice@example.com" {
		t.Errorf("username = %q, want QR account to seed it", p.username)
	}
	e, err := store.Lookup(vault.Key{Kind: vault.KindTOTP, Service: "github", Username: "alice@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if want := (totp.Params{Issuer: "GitHub", Algorithm: "SHA256", Digits: 8, Period: 60}); e.Settings.TOTP != want {
		t.Errorf("code settings = %+v, want the QR code's %+v", e.Settings.TOTP, want)
	}
	if !strings.Contains(creds.DisplayInfo, "Stored TOTP secret") {
		t.Errorf("DisplayInfo = %q", creds.DisplayInfo)
	}
}

func TestStoreTOTP_ManualPath(t *testing.T) {
	stubReadPassword(t, "JBSWY3DPEHPK3PXP")

	p, _ := newTestProvider(vault.NewMemStore())
	p.action = "totp-store"
	p.service = "github"
	p.stdin = strings.NewReader("1\n")

	creds, err := p.GetCredentials()
	if err != nil {
		t.Fatalf("GetCredentials: %v", err)
	}
	if !strings.Contains(creds.DisplayInfo, "Stored TOTP secret for github") {
		t.Errorf("DisplayInfo = %q", creds.DisplayInfo)
	}
}

func TestStoreTOTP_QRScanFailure(t *testing.T) {
	stubScanQRCodeFull(t, qrcode.TOTPInfo{}, errors.New("boom"))

	p, _ := newTestProvider(vault.NewMemStore())
	p.action = "totp-store"
	p.service = "github"
	p.stdin = strings.NewReader("2\n")

	_, err := p.GetCredentials()
	if err == nil || !strings.Contains(err.Error(), "QR code scan failed") {
		t.Errorf("expected QR scan failure, got %v", err)
	}
}

func TestGenerateTOTP_HappyPath(t *testing.T) {
	mock := seeded(t, map[string]string{"totp/github": "JBSWY3DPEHPK3PXP"})

	p, stdout := newTestProvider(mock)
	p.action = "totp-generate"
	p.service = "github"

	creds, err := p.GetCredentials()
	if err != nil {
		t.Fatalf("GetCredentials: %v", err)
	}
	if code := stdout.String(); len(code) != 7 || strings.Trim(code, "0123456789") != "\n" {
		t.Errorf("stdout = %q, want the 6-digit code and a newline", code)
	}
	if creds.DisplayInfo != "" {
		t.Errorf("DisplayInfo = %q, want nothing on stderr", creds.DisplayInfo)
	}
}

func TestGetPassword_ShowKeepsANotesOwnLastNewline(t *testing.T) {
	mock := seeded(t, map[string]string{"secure_note/wifi": "line one\nline two\n"})
	p, stdout := newTestProvider(mock)
	p.action, p.service, p.entryType, p.show = "get", "wifi", "secure_note", true
	if _, err := p.GetCredentials(); err != nil {
		t.Fatalf("GetCredentials: %v", err)
	}
	if stdout.String() != "line one\nline two\n" {
		t.Errorf("stdout = %q, want the note as stored, with no extra newline", stdout.String())
	}
}

func TestExport_WritesJSONToProviderStdout(t *testing.T) {
	mock := seeded(t, map[string]string{"password/github": "s3cret"})

	p, stdout := newTestProvider(mock)
	p.action = "export"
	p.format = "json"

	creds, err := p.GetCredentials()
	if err != nil {
		t.Fatalf("GetCredentials: %v", err)
	}
	if stdout.Len() == 0 {
		t.Fatal("export wrote nothing to p.stdout")
	}
	if !json.Valid(stdout.Bytes()) {
		t.Errorf("export output is not valid JSON: %q", stdout.String())
	}
	if !strings.Contains(creds.DisplayInfo, "Exported") {
		t.Errorf("DisplayInfo = %q, want to mention Exported", creds.DisplayInfo)
	}
}

func TestExport_EncryptedWritesEnvelope(t *testing.T) {
	stubReadPassword(t, "export-password-1234")

	mock := seeded(t, map[string]string{"password/github": "plaintext-secret"})

	p, stdout := newTestProvider(mock)
	p.action = "export"
	p.format = "encrypted"

	creds, err := p.GetCredentials()
	if err != nil {
		t.Fatalf("GetCredentials: %v", err)
	}
	out := stdout.Bytes()
	var envelope struct {
		Algorithm string `json:"algorithm"`
	}
	if err := json.Unmarshal(out, &envelope); err != nil {
		t.Fatalf("envelope is not valid JSON: %v\n%s", err, string(out))
	}
	if envelope.Algorithm != "argon2id" {
		t.Errorf("envelope algorithm = %q, want argon2id\nfull envelope: %s", envelope.Algorithm, string(out))
	}
	if bytes.Contains(out, []byte("plaintext-secret")) {
		t.Fatal("envelope leaked plaintext secret")
	}
	if !strings.Contains(creds.DisplayInfo, "Exported 1") {
		t.Errorf("DisplayInfo = %q", creds.DisplayInfo)
	}
}

func TestExport_EncryptedPasswordMismatch(t *testing.T) {
	calls := 0
	orig := readPassword
	readPassword = func() ([]byte, error) {
		calls++
		if calls == 1 {
			return []byte("first-password"), nil
		}
		return []byte("second-password"), nil
	}
	t.Cleanup(func() { readPassword = orig })

	mock := vault.NewMemStore()
	p, _ := newTestProvider(mock)
	p.action = "export"
	p.format = "encrypted"

	_, err := p.GetCredentials()
	if err == nil || !strings.Contains(err.Error(), "do not match") {
		t.Fatalf("expected mismatch error, got %v", err)
	}
}

func TestExport_EncryptedEmptyPassword(t *testing.T) {
	stubReadPassword(t, "")

	mock := vault.NewMemStore()
	p, _ := newTestProvider(mock)
	p.action = "export"
	p.format = "encrypted"

	_, err := p.GetCredentials()
	if err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("expected empty-password error, got %v", err)
	}
}

func TestImport_EncryptedRoundTripThroughProvider(t *testing.T) {
	stubReadPassword(t, "round-trip-password")

	pSrc, srcOut := newTestProvider(seeded(t, map[string]string{"password/github/alice": "hunter2"}))
	pSrc.action = "export"
	pSrc.format = "encrypted"
	if _, err := pSrc.GetCredentials(); err != nil {
		t.Fatalf("export: %v", err)
	}

	dest := vault.NewMemStore()
	pDest, _ := newTestProvider(dest)
	pDest.action = "import"
	pDest.format = "encrypted"
	pDest.stdin = bytes.NewReader(srcOut.Bytes())

	creds, err := pDest.GetCredentials()
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if !strings.Contains(creds.DisplayInfo, "Imported 1") {
		t.Errorf("DisplayInfo = %q", creds.DisplayInfo)
	}
	if got := stored(t, dest, "password/github/alice"); got != "hunter2" {
		t.Errorf("stored secret = %q, want hunter2", got)
	}
}

func TestImport_EncryptedWrongPassword(t *testing.T) {
	calls := 0
	orig := readPassword
	readPassword = func() ([]byte, error) {
		calls++
		switch calls {
		case 1, 2:
			return []byte("password-a"), nil
		default:
			return []byte("password-b"), nil
		}
	}
	t.Cleanup(func() { readPassword = orig })

	pSrc, srcOut := newTestProvider(seeded(t, map[string]string{"password/github": "s"}))
	pSrc.action = "export"
	pSrc.format = "encrypted"
	if _, err := pSrc.GetCredentials(); err != nil {
		t.Fatalf("export: %v", err)
	}

	pDest, _ := newTestProvider(vault.NewMemStore())
	pDest.action = "import"
	pDest.format = "encrypted"
	pDest.stdin = bytes.NewReader(srcOut.Bytes())

	_, err := pDest.GetCredentials()
	if err == nil {
		t.Fatal("expected error for wrong password")
	}
}

func TestImport_ReadsFromProviderStdin(t *testing.T) {
	store := vault.NewMemStore()
	p, _ := newTestProvider(store)
	p.action = "import"
	p.format = "json"
	p.stdin = strings.NewReader(`[{"service":"github","username":"alice","type":"password","secret":"s3cret"}]`)

	creds, err := p.GetCredentials()
	if err != nil {
		t.Fatalf("GetCredentials: %v", err)
	}
	if got := stored(t, store, "password/github/alice"); got != "s3cret" {
		t.Errorf("stored secret = %q, want s3cret", got)
	}
	if !strings.Contains(creds.DisplayInfo, "Imported 1 entry") {
		t.Errorf("DisplayInfo = %q", creds.DisplayInfo)
	}
}

func TestGetFlagInfo(t *testing.T) {
	p := NewProvider(vault.NewMemStore())
	flags := p.GetFlagInfo()
	if len(flags) == 0 {
		t.Fatal("expected flag info")
	}

	names := make(map[string]bool)
	for _, f := range flags {
		names[f.Name] = true
	}

	for _, expected := range []string{"action", "service-name", "username", "entry-type", "query", "sort", "format", "show", "force", "limit", "offset"} {
		if !names[expected] {
			t.Errorf("missing flag %q in GetFlagInfo", expected)
		}
	}
}

func TestEntryCount(t *testing.T) {
	for n, want := range map[int]string{0: "0 entries", 1: "1 entry", 2: "2 entries"} {
		if got := entryCount(n); got != want {
			t.Errorf("entryCount(%d) = %q, want %q", n, got, want)
		}
	}
}

// A name no entry can have is refused before anything is asked, and
// without the vault (CheckNames).
func TestValidateRequest_RefusesBadNames(t *testing.T) {
	// "" is --clip without --action, which gets the entry.
	for _, action := range []string{"", "store", "generate", "get", "totp-store", "totp-generate"} {
		for name, tt := range map[string]struct{ service, username, wantSub string }{
			"trailing space": {"github ", "", `the service name "github " starts or ends with a space`},
			"leading space":  {"github", " alice", `the username " alice" starts or ends with a space`},
			"long name":      {strings.Repeat("s", 257), "", "the service name is 257 characters long; the most is 256"},
		} {
			p, _ := newTestProvider(vault.NewMemStore())
			p.action, p.service, p.username = action, tt.service, tt.username
			if err := p.ValidateRequest(); err == nil || !strings.Contains(err.Error(), tt.wantSub) {
				t.Errorf("%s, %s: ValidateRequest = %v, want it to contain %q", action, name, err, tt.wantSub)
			}
		}
	}
}

// Refused entries are named as --list names them, quoted so a stray space shows.
func TestImport_ReportsRefusedEntriesByName(t *testing.T) {
	p, _ := newTestProvider(vault.NewMemStore())
	p.action, p.format = "import", "json"
	p.stdin = strings.NewReader(`[{"service":"github ","type":"password","secret":"a"},
		{"service":"gitlab","username":"alice","type":"password","secret":""},
		{"service":"ok","type":"password","secret":"b"}]`)
	creds, err := p.GetCredentials()
	if err != nil {
		t.Fatalf("GetCredentials: %v", err)
	}
	for _, want := range []string{
		"Imported 1 entry, 2 errors:",
		`"github ": the service name "github " starts or ends with a space`,
		`"gitlab" ("alice"): empty secret`,
	} {
		if !strings.Contains(creds.DisplayInfo, want) {
			t.Errorf("DisplayInfo = %q, want it to contain %q", creds.DisplayInfo, want)
		}
	}
}

func TestImport_OneErrorIsSingular(t *testing.T) {
	p, _ := newTestProvider(vault.NewMemStore())
	p.action, p.format = "import", "json"
	p.stdin = strings.NewReader(`[{"service":"a/b","type":"password","secret":"a"}]`)
	creds, err := p.GetCredentials()
	if err != nil {
		t.Fatalf("GetCredentials: %v", err)
	}
	if !strings.Contains(creds.DisplayInfo, "Imported 0 entries, 1 error:") {
		t.Errorf("DisplayInfo = %q", creds.DisplayInfo)
	}
}

// A username taken from a QR code is checked like one given as a flag,
// before anything is stored.
func TestStoreTOTP_QRAccountIsCheckedToo(t *testing.T) {
	stubScanQRCodeFull(t, qrcode.TOTPInfo{Secret: "JBSWY3DPEHPK3PXP", Account: strings.Repeat("a", 300)}, nil)
	store := vault.NewMemStore()
	p, _ := newTestProvider(store)
	p.action, p.service = "totp-store", "github"
	p.stdin = strings.NewReader("2\n")
	defer testutil.DiscardStderr(t)()
	if _, err := p.GetCredentials(); err == nil || !strings.Contains(err.Error(), "the QR code's account name can't be used: the username is 300 characters long; the most is 256; choose one with --username") {
		t.Errorf("err = %v, want the QR account refused", err)
	}
	if entries, err := store.List(vault.Filter{}); err != nil || len(entries) != 0 {
		t.Errorf("stored %v (%v), want nothing", entries, err)
	}
}

func TestDeleteEntry_RefusesABadName(t *testing.T) {
	p, _ := newTestProvider(vault.NewMemStore())
	if err := p.DeleteEntry("password/github "); err == nil || !strings.Contains(err.Error(), "starts or ends with a space") {
		t.Errorf("DeleteEntry = %v, want the space refused", err)
	}
}

func TestCheckNames_NeedsNoVault(t *testing.T) {
	p := NewProvider(nil)
	p.action, p.service = "store", "github "
	if err := p.CheckNames(); err == nil || !strings.Contains(err.Error(), "starts or ends with a space") {
		t.Errorf("CheckNames = %v, want the space refused", err)
	}
	p.service = "github"
	if err := p.CheckNames(); err != nil {
		t.Errorf("CheckNames of a good name = %v", err)
	}
}
