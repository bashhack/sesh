package password

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"strings"
	"testing"

	"github.com/bashhack/sesh/internal/keychain"
	"github.com/bashhack/sesh/internal/keychain/mocks"
	"github.com/bashhack/sesh/internal/password"
	"github.com/bashhack/sesh/internal/qrcode"
)

func TestName(t *testing.T) {
	p := NewProvider(&mocks.MockProvider{})
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

func TestListEntriesWithFilters(t *testing.T) {
	mock := &mocks.MockProvider{
		ListEntriesFunc: func(service string) ([]keychain.KeychainEntry, error) {
			return []keychain.KeychainEntry{
				{Service: "sesh-password/password/github/user1", Account: "alice"},
				{Service: "sesh-password/api_key/stripe", Account: "alice"},
				{Service: "sesh-password/password/gitlab/user2", Account: "alice"},
			}, nil
		},
		SetDescriptionFunc: func(service, account, description string) error { return nil },
	}

	tests := map[string]struct {
		entryType string
		sortBy    string
		limit     int
		offset    int
		expected  int
	}{
		"no filters": {
			entryType: "", sortBy: "service", expected: 3,
		},
		"filter api_key": {
			entryType: "api_key", sortBy: "service", expected: 1,
		},
		"filter password": {
			entryType: "password", sortBy: "service", expected: 2,
		},
		"with limit": {
			entryType: "", sortBy: "service", limit: 2, expected: 2,
		},
		"with offset": {
			entryType: "", sortBy: "service", offset: 2, expected: 1,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			p := &Provider{
				keychain:  mock,
				entryType: tc.entryType,
				sortBy:    tc.sortBy,
				limit:     tc.limit,
				offset:    tc.offset,
			}
			p.User = "alice"

			entries, err := p.ListEntries()
			if err != nil {
				t.Fatalf("ListEntries: %v", err)
			}
			if len(entries) != tc.expected {
				t.Errorf("expected %d entries, got %d", tc.expected, len(entries))
			}
		})
	}
}

func TestHighlightMatch(t *testing.T) {
	tests := map[string]struct {
		text     string
		query    string
		expected string
	}{
		"match at start": {
			text: "github", query: "git",
			expected: "\033[1mgit\033[0mhub",
		},
		"match in middle": {
			text: "my-github-account", query: "github",
			expected: "my-\033[1mgithub\033[0m-account",
		},
		"no match": {
			text: "stripe", query: "github",
			expected: "stripe",
		},
		"case insensitive match": {
			text: "GitHub", query: "github",
			expected: "\033[1mGitHub\033[0m",
		},
		"non-ASCII text skips highlighting": {
			// Turkish "İ" lowercases to "i\u0307" (two bytes becomes three),
			// so byte-level slicing could land mid-rune; bail out cleanly.
			text: "İstanbul", query: "stan",
			expected: "İstanbul",
		},
		"non-ASCII query skips highlighting": {
			text: "strasse", query: "ß",
			expected: "strasse",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got := highlightMatch(tc.text, tc.query)
			if got != tc.expected {
				t.Errorf("highlightMatch(%q, %q) = %q, want %q", tc.text, tc.query, got, tc.expected)
			}
		})
	}
}

func TestDeleteEntryWithForce(t *testing.T) {
	deleted := false
	mock := &mocks.MockProvider{
		DeleteEntryFunc: func(account, service string) error {
			deleted = true
			return nil
		},
	}

	p := &Provider{keychain: mock, force: true}
	err := p.DeleteEntry("sesh-password/password/github/user1:alice")
	if err != nil {
		t.Fatalf("DeleteEntry: %v", err)
	}
	if !deleted {
		t.Error("expected entry to be deleted")
	}
}

func TestDescription(t *testing.T) {
	p := NewProvider(&mocks.MockProvider{})
	if p.Description() == "" {
		t.Error("Description should not be empty")
	}
}

func TestGetSetupHandler(t *testing.T) {
	// Password provider has no interactive setup wizard — ensure it
	// returns nil so the setup dispatcher doesn't try to invoke one.
	if h := NewProvider(&mocks.MockProvider{}).GetSetupHandler(); h != nil {
		t.Errorf("GetSetupHandler() = %v, want nil", h)
	}
}

func TestSuppressActionFraming(t *testing.T) {
	if !NewProvider(&mocks.MockProvider{}).SuppressActionFraming() {
		t.Error("SuppressActionFraming() = false, want true")
	}
}

func TestSetupFlags(t *testing.T) {
	p := NewProvider(&mocks.MockProvider{})
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
	if p.User == "" {
		t.Error("User should default to current OS user")
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
			p := &Provider{keychain: &mocks.MockProvider{}, entryType: entryType}
			if got := p.effectiveEntryType(); got != want {
				t.Errorf("effectiveEntryType(%q) = %v, want %v", entryType, got, want)
			}
		})
	}
}

func TestDeleteEntry_InvalidID(t *testing.T) {
	p := &Provider{keychain: &mocks.MockProvider{}, force: true}
	err := p.DeleteEntry("not-a-valid-id")
	if err == nil {
		t.Fatal("expected error for malformed entry ID")
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
func newTestProvider(kc keychain.Provider) (*Provider, *bytes.Buffer) {
	p := NewProvider(kc)
	p.User = "testuser"
	var stdout bytes.Buffer
	p.stdout = &stdout
	p.stdin = strings.NewReader("")
	return p, &stdout
}

func TestStorePassword_HappyPath(t *testing.T) {
	stubReadPassword(t, "s3cret")

	var storedKey, storedAccount string
	var storedSecret []byte
	mock := &mocks.MockProvider{
		SetSecretFunc: func(account, service string, secret []byte) error {
			storedAccount = account
			storedKey = service
			storedSecret = append([]byte(nil), secret...)
			return nil
		},
		SetDescriptionFunc: func(_, _, _ string) error { return nil },
	}

	p, _ := newTestProvider(mock)
	p.action = "store"
	p.service = "github"
	p.username = "alice"
	p.force = true

	creds, err := p.GetCredentials()
	if err != nil {
		t.Fatalf("GetCredentials: %v", err)
	}
	if string(storedSecret) != "s3cret" {
		t.Errorf("stored secret = %q, want s3cret", storedSecret)
	}
	if storedAccount != "testuser" {
		t.Errorf("stored account = %q, want testuser", storedAccount)
	}
	if !strings.Contains(storedKey, "github") {
		t.Errorf("stored service key = %q, want contains github", storedKey)
	}
	if !strings.Contains(creds.DisplayInfo, "Stored password for github") {
		t.Errorf("DisplayInfo = %q, want contains 'Stored password for github'", creds.DisplayInfo)
	}
}

func TestStorePassword_OverwriteRefusedOnPipedStdin(t *testing.T) {
	stubStdinIsTerminal(t, false)

	mock := &mocks.MockProvider{
		ListEntriesFunc: func(service string) ([]keychain.KeychainEntry, error) {
			return []keychain.KeychainEntry{
				{Service: service, Account: "testuser"},
			}, nil
		},
	}

	p, _ := newTestProvider(mock)
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

	var storedSecret []byte
	mock := &mocks.MockProvider{
		SetSecretFunc: func(_, _ string, secret []byte) error {
			storedSecret = append([]byte(nil), secret...)
			return nil
		},
		SetDescriptionFunc: func(_, _, _ string) error { return nil },
	}

	p, _ := newTestProvider(mock)
	p.action = "store"
	p.service = "diary"
	p.entryType = "secure_note"
	p.force = true
	p.stdin = strings.NewReader("line one\nline two\n")

	if _, err := p.GetCredentials(); err != nil {
		t.Fatalf("GetCredentials: %v", err)
	}
	if string(storedSecret) != "line one\nline two\n" {
		t.Errorf("stored note = %q, want multiline body", storedSecret)
	}
}

func TestGeneratePassword_HappyPathClipboardMode(t *testing.T) {
	mock := &mocks.MockProvider{
		SetSecretFunc:      func(_, _ string, _ []byte) error { return nil },
		SetDescriptionFunc: func(_, _, _ string) error { return nil },
	}

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
	mock := &mocks.MockProvider{
		SetSecretFunc:      func(_, _ string, _ []byte) error { return nil },
		SetDescriptionFunc: func(_, _, _ string) error { return nil },
	}

	p, _ := newTestProvider(mock)
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
	if !strings.Contains(creds.DisplayInfo, "Generated and stored password for github") {
		t.Errorf("DisplayInfo = %q, missing status line", creds.DisplayInfo)
	}
}

func TestGeneratePassword_JSONFormat(t *testing.T) {
	mock := &mocks.MockProvider{
		SetSecretFunc:      func(_, _ string, _ []byte) error { return nil },
		SetDescriptionFunc: func(_, _, _ string) error { return nil },
	}

	p, _ := newTestProvider(mock)
	p.action = "generate"
	p.service = "github"
	p.username = "alice"
	p.pwLength = 16
	p.format = "json"

	creds, err := p.GetCredentials()
	if err != nil {
		t.Fatalf("GetCredentials: %v", err)
	}
	var payload struct {
		Service  string `json:"service"`
		Username string `json:"username"`
		Type     string `json:"type"`
		Password string `json:"password"`
	}
	if err := json.Unmarshal([]byte(creds.DisplayInfo), &payload); err != nil {
		t.Fatalf("DisplayInfo not JSON: %v (raw %q)", err, creds.DisplayInfo)
	}
	if payload.Service != "github" || payload.Username != "alice" || payload.Type != "password" {
		t.Errorf("JSON header mismatch: %+v", payload)
	}
	if len(payload.Password) != 16 {
		t.Errorf("password length = %d, want 16", len(payload.Password))
	}
}

func TestGetPassword_ShowReturnsPlainSecret(t *testing.T) {
	mock := &mocks.MockProvider{
		GetSecretFunc: func(_, _ string) ([]byte, error) {
			return []byte("s3cret"), nil
		},
	}

	p, _ := newTestProvider(mock)
	p.action = "get"
	p.service = "github"
	p.show = true

	creds, err := p.GetCredentials()
	if err != nil {
		t.Fatalf("GetCredentials: %v", err)
	}
	if creds.DisplayInfo != "s3cret" {
		t.Errorf("DisplayInfo = %q, want s3cret", creds.DisplayInfo)
	}
	if creds.CopyValue != "" {
		t.Errorf("CopyValue should be empty in --show mode, got %q", creds.CopyValue)
	}
}

func TestGetPassword_DefaultUsesClipboardPayload(t *testing.T) {
	mock := &mocks.MockProvider{
		GetSecretFunc: func(_, _ string) ([]byte, error) {
			return []byte("s3cret"), nil
		},
	}

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
	mock := &mocks.MockProvider{
		GetSecretFunc: func(_, _ string) ([]byte, error) {
			return []byte("s3cret"), nil
		},
	}

	p, _ := newTestProvider(mock)
	p.action = "get"
	p.service = "github"
	p.format = "json"

	creds, err := p.GetCredentials()
	if err != nil {
		t.Fatalf("GetCredentials: %v", err)
	}
	var payload struct {
		Password string `json:"password"`
	}
	if err := json.Unmarshal([]byte(creds.DisplayInfo), &payload); err != nil {
		t.Fatalf("DisplayInfo not JSON: %v (raw %q)", err, creds.DisplayInfo)
	}
	if payload.Password != "s3cret" {
		t.Errorf("json.password = %q, want s3cret", payload.Password)
	}
}

func TestSearchPasswords_NoMatches(t *testing.T) {
	mock := &mocks.MockProvider{
		ListEntriesFunc: func(_ string) ([]keychain.KeychainEntry, error) {
			return nil, nil
		},
	}

	p, _ := newTestProvider(mock)
	p.action = "search"
	p.query = "nonexistent"

	creds, err := p.GetCredentials()
	if err != nil {
		t.Fatalf("GetCredentials: %v", err)
	}
	if !strings.Contains(creds.DisplayInfo, "No entries matching") {
		t.Errorf("DisplayInfo = %q, want 'No entries matching'", creds.DisplayInfo)
	}
}

func TestSearchPasswords_MatchingEntries(t *testing.T) {
	mock := &mocks.MockProvider{
		ListEntriesFunc: func(_ string) ([]keychain.KeychainEntry, error) {
			return []keychain.KeychainEntry{
				{Service: "sesh-password/password/github/alice", Account: "testuser"},
				{Service: "sesh-password/password/stripe", Account: "testuser"},
			}, nil
		},
	}

	p, _ := newTestProvider(mock)
	p.action = "search"
	p.query = "git"

	creds, err := p.GetCredentials()
	if err != nil {
		t.Fatalf("GetCredentials: %v", err)
	}
	if !strings.Contains(creds.DisplayInfo, "Found 1 entries") {
		t.Errorf("DisplayInfo = %q, want to include 'Found 1 entries'", creds.DisplayInfo)
	}
	// "github" prints with the matched "git" wrapped in ANSI bold, so the
	// literal substring isn't contiguous — check for the unhighlighted tail.
	if !strings.Contains(creds.DisplayInfo, "hub") {
		t.Errorf("DisplayInfo = %q, want to include the matched entry", creds.DisplayInfo)
	}
}

func TestDeleteEntry_CancelsOnNo(t *testing.T) {
	deleted := false
	mock := &mocks.MockProvider{
		DeleteEntryFunc: func(_, _ string) error {
			deleted = true
			return nil
		},
	}

	p, _ := newTestProvider(mock)
	p.stdin = strings.NewReader("n\n")

	err := p.DeleteEntry("sesh-password/password/github/user1:alice")
	if err == nil || !strings.Contains(err.Error(), "delete cancelled") {
		t.Errorf("expected delete-cancelled error, got %v", err)
	}
	if deleted {
		t.Error("DeleteEntry should not have been called when user answered n")
	}
}

func TestDeleteEntry_ConfirmsOnYes(t *testing.T) {
	deleted := false
	mock := &mocks.MockProvider{
		DeleteEntryFunc: func(_, _ string) error {
			deleted = true
			return nil
		},
	}

	p, _ := newTestProvider(mock)
	p.stdin = strings.NewReader("y\n")

	if err := p.DeleteEntry("sesh-password/password/github/user1:alice"); err != nil {
		t.Fatalf("DeleteEntry: %v", err)
	}
	if !deleted {
		t.Error("DeleteEntry should have been called when user answered y")
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

	var gotDesc string
	mock := &mocks.MockProvider{
		SetSecretFunc:       func(_, _ string, _ []byte) error { return nil },
		SetSecretStringFunc: func(_, _, _ string) error { return nil },
		SetDescriptionFunc: func(_, _, description string) error {
			gotDesc = description
			return nil
		},
	}

	p, _ := newTestProvider(mock)
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
	if !strings.Contains(gotDesc, "GitHub") {
		t.Errorf("SetDescription payload = %q, want to carry issuer", gotDesc)
	}
	if !strings.Contains(creds.DisplayInfo, "Stored TOTP secret") {
		t.Errorf("DisplayInfo = %q", creds.DisplayInfo)
	}
}

func TestStoreTOTP_ManualPath(t *testing.T) {
	stubReadPassword(t, "JBSWY3DPEHPK3PXP")

	mock := &mocks.MockProvider{
		SetSecretFunc:       func(_, _ string, _ []byte) error { return nil },
		SetSecretStringFunc: func(_, _, _ string) error { return nil },
		SetDescriptionFunc:  func(_, _, _ string) error { return nil },
	}

	p, _ := newTestProvider(mock)
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

	p, _ := newTestProvider(&mocks.MockProvider{})
	p.action = "totp-store"
	p.service = "github"
	p.stdin = strings.NewReader("2\n")

	_, err := p.GetCredentials()
	if err == nil || !strings.Contains(err.Error(), "QR code scan failed") {
		t.Errorf("expected QR scan failure, got %v", err)
	}
}

func TestGenerateTOTP_HappyPath(t *testing.T) {
	mock := &mocks.MockProvider{
		GetSecretFunc: func(_, _ string) ([]byte, error) {
			return []byte("JBSWY3DPEHPK3PXP"), nil
		},
		ListEntriesFunc: func(_ string) ([]keychain.KeychainEntry, error) {
			return nil, nil
		},
	}

	p, _ := newTestProvider(mock)
	p.action = "totp-generate"
	p.service = "github"

	creds, err := p.GetCredentials()
	if err != nil {
		t.Fatalf("GetCredentials: %v", err)
	}
	if len(creds.CopyValue) != 6 {
		t.Errorf("TOTP code length = %d, want 6", len(creds.CopyValue))
	}
	if !strings.Contains(creds.DisplayInfo, "TOTP code:") {
		t.Errorf("DisplayInfo = %q", creds.DisplayInfo)
	}
}

func TestExport_WritesJSONToProviderStdout(t *testing.T) {
	mock := &mocks.MockProvider{
		ListEntriesFunc: func(_ string) ([]keychain.KeychainEntry, error) {
			return []keychain.KeychainEntry{
				{Service: "sesh-password/password/github", Account: "testuser"},
			}, nil
		},
		GetSecretFunc: func(_, _ string) ([]byte, error) {
			return []byte("s3cret"), nil
		},
	}

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

	mock := &mocks.MockProvider{
		ListEntriesFunc: func(_ string) ([]keychain.KeychainEntry, error) {
			return []keychain.KeychainEntry{
				{Service: "sesh-password/password/github", Account: "testuser"},
			}, nil
		},
		GetSecretFunc: func(_, _ string) ([]byte, error) {
			return []byte("plaintext-secret"), nil
		},
	}

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

	mock := &mocks.MockProvider{
		ListEntriesFunc: func(_ string) ([]keychain.KeychainEntry, error) { return nil, nil },
	}
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

	mock := &mocks.MockProvider{
		ListEntriesFunc: func(_ string) ([]keychain.KeychainEntry, error) { return nil, nil },
	}
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

	srcMock := &mocks.MockProvider{
		ListEntriesFunc: func(_ string) ([]keychain.KeychainEntry, error) {
			return []keychain.KeychainEntry{
				// Account must match the manager's user (set by newTestProvider
				// to "testuser") or parseEntry silently drops the row. The
				// username "alice" lives in the service-key path segment.
				{Service: "sesh-password/password/github/alice", Account: "testuser"},
			}, nil
		},
		GetSecretFunc: func(_, _ string) ([]byte, error) {
			return []byte("hunter2"), nil
		},
	}

	pSrc, srcOut := newTestProvider(srcMock)
	pSrc.action = "export"
	pSrc.format = "encrypted"
	if _, err := pSrc.GetCredentials(); err != nil {
		t.Fatalf("export: %v", err)
	}
	envelope := srcOut.Bytes()

	stored := map[string][]byte{}
	destMock := &mocks.MockProvider{
		GetSecretFunc: func(_, service string) ([]byte, error) {
			if v, ok := stored[service]; ok {
				return v, nil
			}
			return nil, keychain.ErrNotFound
		},
		SetSecretFunc: func(_, service string, secret []byte) error {
			stored[service] = append([]byte(nil), secret...)
			return nil
		},
		SetDescriptionFunc: func(_, _, _ string) error { return nil },
		ListEntriesFunc:    func(_ string) ([]keychain.KeychainEntry, error) { return nil, nil },
	}
	pDest, _ := newTestProvider(destMock)
	pDest.action = "import"
	pDest.format = "encrypted"
	pDest.stdin = bytes.NewReader(envelope)

	creds, err := pDest.GetCredentials()
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if !strings.Contains(creds.DisplayInfo, "Imported 1") {
		t.Errorf("DisplayInfo = %q", creds.DisplayInfo)
	}
	if got := stored["sesh-password/password/github/alice"]; string(got) != "hunter2" {
		t.Errorf("stored secret = %q, want hunter2 (full map: %v)", got, stored)
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

	srcMock := &mocks.MockProvider{
		ListEntriesFunc: func(_ string) ([]keychain.KeychainEntry, error) {
			return []keychain.KeychainEntry{
				{Service: "sesh-password/password/github", Account: "alice"},
			}, nil
		},
		GetSecretFunc: func(_, _ string) ([]byte, error) { return []byte("s"), nil },
	}
	pSrc, srcOut := newTestProvider(srcMock)
	pSrc.action = "export"
	pSrc.format = "encrypted"
	if _, err := pSrc.GetCredentials(); err != nil {
		t.Fatalf("export: %v", err)
	}

	destMock := &mocks.MockProvider{}
	pDest, _ := newTestProvider(destMock)
	pDest.action = "import"
	pDest.format = "encrypted"
	pDest.stdin = bytes.NewReader(srcOut.Bytes())

	_, err := pDest.GetCredentials()
	if err == nil {
		t.Fatal("expected error for wrong password")
	}
}

func TestImport_ReadsFromProviderStdin(t *testing.T) {
	var stored int
	mock := &mocks.MockProvider{
		SetSecretFunc: func(_, _ string, _ []byte) error {
			stored++
			return nil
		},
		SetSecretStringFunc: func(_, _, _ string) error { return nil },
		SetDescriptionFunc:  func(_, _, _ string) error { return nil },
		// Existence probe during import treats nil/nil as "exists". Return
		// ErrNotFound so the entry is treated as new and StorePassword runs.
		GetSecretFunc: func(_, _ string) ([]byte, error) {
			return nil, keychain.ErrNotFound
		},
		ListEntriesFunc: func(_ string) ([]keychain.KeychainEntry, error) { return nil, nil },
	}

	body := `[{"service":"github","username":"alice","type":"password","secret":"s3cret"}]`
	p, _ := newTestProvider(mock)
	p.action = "import"
	p.format = "json"
	p.stdin = strings.NewReader(body)

	creds, err := p.GetCredentials()
	if err != nil {
		t.Fatalf("GetCredentials: %v", err)
	}
	if stored != 1 {
		t.Errorf("SetSecret calls = %d, want 1", stored)
	}
	if !strings.Contains(creds.DisplayInfo, "Imported 1 entries") {
		t.Errorf("DisplayInfo = %q", creds.DisplayInfo)
	}
}

func TestGetFlagInfo(t *testing.T) {
	p := NewProvider(&mocks.MockProvider{})
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
