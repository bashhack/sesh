package totp

import (
	"errors"
	"flag"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/bashhack/sesh/internal/password"
	"github.com/bashhack/sesh/internal/provider"
	"github.com/bashhack/sesh/internal/setup"
	"github.com/bashhack/sesh/internal/testutil"
	internalTotp "github.com/bashhack/sesh/internal/totp"
	totpMocks "github.com/bashhack/sesh/internal/totp/mocks"
	"github.com/bashhack/sesh/internal/vault"
)

// totpKey is the TOTP entry for service, with profile as its username.
func totpKey(service, profile string) vault.Key {
	return vault.Key{Kind: vault.KindTOTP, Service: service, Username: profile}
}

// seeded is a store holding the TOTP entries given, each with secret.
func seeded(t *testing.T, secrets map[vault.Key]string) *vault.MemStore {
	t.Helper()
	store := vault.NewMemStore()
	for k, s := range secrets {
		if err := store.Put(k, []byte(s)); err != nil {
			t.Fatal(err)
		}
	}
	return store
}

// failingStore is a MemStore whose every read and write fails with err.
type failingStore struct {
	*vault.MemStore
	err error
}

func (f failingStore) Get(vault.Key) ([]byte, error)             { return nil, f.err }
func (f failingStore) Lookup(vault.Key) (vault.Entry, error)     { return vault.Entry{}, f.err }
func (f failingStore) Exists(vault.Key) error                    { return f.err }
func (f failingStore) List(*vault.Filter) ([]vault.Entry, error) { return nil, f.err }
func (f failingStore) Delete(vault.Key) error                    { return f.err }
func (f failingStore) DeleteMany([]vault.Key) error              { return f.err }

func TestNewProvider(t *testing.T) {
	store := vault.NewMemStore()
	mockTOTP := &totpMocks.MockProvider{}

	p := NewProvider(store, mockTOTP)

	if p == nil {
		t.Fatal("NewProvider() returned nil")
	}
	if p.store != store {
		t.Error("store not set correctly")
	}
	if p.totp != mockTOTP {
		t.Error("TOTP provider not set correctly")
	}
}

func TestProvider_Name(t *testing.T) {
	p := &Provider{}
	if got := p.Name(); got != "totp" {
		t.Errorf("Name() = %v, want %v", got, "totp")
	}
}

func TestProvider_Description(t *testing.T) {
	p := &Provider{}
	want := "Generic TOTP provider for any service"
	if got := p.Description(); got != want {
		t.Errorf("Description() = %v, want %v", got, want)
	}
}

func TestProvider_SetupFlags(t *testing.T) {
	p := &Provider{}
	fs := flag.NewFlagSet("test", flag.ContinueOnError)

	if err := p.SetupFlags(fs); err != nil {
		t.Fatalf("SetupFlags() unexpected error: %v", err)
	}
	if err := fs.Parse([]string{"--service-name", "github", "--profile", "work"}); err != nil {
		t.Errorf("Parse() error: %v", err)
	}
	if p.key() != totpKey("github", "work") {
		t.Errorf("key() = %+v, want the TOTP entry github/work", p.key())
	}
}

func TestProvider_GetFlagInfo(t *testing.T) {
	p := &Provider{}
	flags := p.GetFlagInfo()

	if len(flags) != 5 || flags[2].Name != "force" || flags[2].Type != "bool" || flags[3].Name != "folder" || flags[4].Name != "tag" {
		t.Fatalf("GetFlagInfo() = %+v, want service-name, profile, force, folder and tag", flags)
	}

	if flags[0].Name != "service-name" {
		t.Errorf("flag[0].Name = %v, want 'service-name'", flags[0].Name)
	}
	if !flags[0].Required {
		t.Error("service-name flag should be required")
	}

	if flags[1].Name != "profile" {
		t.Errorf("flag[1].Name = %v, want 'profile'", flags[1].Name)
	}
	if flags[1].Required {
		t.Error("profile flag should not be required")
	}
}

func TestProvider_GetSetupHandler(t *testing.T) {
	p := &Provider{store: vault.NewMemStore()}

	handler := p.GetSetupHandler()
	if handler == nil {
		t.Fatal("GetSetupHandler() returned nil")
	}

	totpHandler, ok := handler.(*setup.TOTPSetupHandler)
	if !ok {
		t.Fatalf("GetSetupHandler() returned %T, want *setup.TOTPSetupHandler", handler)
	}
	if totpHandler.ServiceName() != "totp" {
		t.Errorf("handler.ServiceName() = %v, want 'totp'", totpHandler.ServiceName())
	}
}

func TestProvider_ValidateRequest(t *testing.T) {
	tests := map[string]struct {
		store       vault.Store
		serviceName string
		profile     string
		wantErrMsg  string
	}{
		"valid request": {
			store:       seeded(t, map[vault.Key]string{totpKey("github", ""): "secret"}),
			serviceName: "github",
		},
		"valid request with profile": {
			store:       seeded(t, map[vault.Key]string{totpKey("github", "work"): "secret"}),
			serviceName: "github",
			profile:     "work",
		},
		"no TOTP secret for service": {
			store:       seeded(t, map[vault.Key]string{totpKey("github", ""): "secret"}),
			serviceName: "gitlab",
			wantErrMsg:  "no TOTP entry found for service 'gitlab'. Run 'sesh --service totp --setup' first",
		},
		"no TOTP secret for service with profile": {
			// The entry without a profile isn't the one asked for.
			store:       seeded(t, map[vault.Key]string{totpKey("gitlab", ""): "secret"}),
			serviceName: "gitlab",
			profile:     "work",
			wantErrMsg:  "no TOTP entry found for service 'gitlab' with profile 'work'. Run 'sesh --service totp --setup' first",
		},
		"another kind under the same name isn't a TOTP entry": {
			store:       seeded(t, map[vault.Key]string{{Kind: vault.KindPassword, Service: "gitlab"}: "pw"}),
			serviceName: "gitlab",
			wantErrMsg:  "no TOTP entry found for service 'gitlab'. Run 'sesh --service totp --setup' first",
		},
		"an entry in another case is suggested": {
			store:       seeded(t, map[vault.Key]string{totpKey("GitHub", "work"): "secret"}),
			serviceName: "github",
			profile:     "work",
			wantErrMsg:  "no TOTP entry found for service 'github' with profile 'work'; did you mean GitHub (work)? Names are case-sensitive",
		},
		"store error surfaces without fallback message": {
			store:       failingStore{MemStore: vault.NewMemStore(), err: errors.New("vault locked")},
			serviceName: "github",
			wantErrMsg:  "failed to look up the TOTP entry: vault locked",
		},
		"empty service name": {
			store:       failingStore{MemStore: vault.NewMemStore(), err: errors.New("the store shouldn't be asked")},
			serviceName: "",
			wantErrMsg:  "--service-name is required for TOTP provider",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			p := &Provider{
				store:       tc.store,
				serviceName: tc.serviceName,
				profile:     tc.profile,
			}

			err := p.ValidateRequest()
			if tc.wantErrMsg == "" {
				if err != nil {
					t.Errorf("ValidateRequest() unexpected error: %v", err)
				}
				return
			}
			if err == nil || err.Error() != tc.wantErrMsg {
				t.Errorf("ValidateRequest() = %v, want %q", err, tc.wantErrMsg)
			}
		})
	}
}

func TestProvider_GetCredentials_StderrHintQuoting(t *testing.T) {
	tests := map[string]struct {
		serviceName string
		profile     string
		wantSubstr  string
	}{
		"simple service name": {
			serviceName: "github",
			wantSubstr:  `--service-name github --clip`,
		},
		"service name with spaces": {
			serviceName: "my service",
			wantSubstr:  `--service-name 'my service'`,
		},
		"profile with spaces": {
			serviceName: "github",
			profile:     "work account",
			wantSubstr:  `--profile 'work account'`,
		},
		// Double quotes would let the shell expand $ and backticks.
		"a dollar sign": {
			serviceName: "pay$ite",
			wantSubstr:  `--service-name 'pay$ite'`,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			restore := testutil.RedirectStderr(t)
			stubStdoutIsTerminal(t, true)

			mockTOTP := &totpMocks.MockProvider{
				GenerateConsecutiveCodesBytesFunc: func(secret []byte) (string, string, error) {
					return "123456", "654321", nil
				},
			}

			p := &Provider{
				store:       seeded(t, map[vault.Key]string{totpKey(tc.serviceName, tc.profile): "MYSECRET"}),
				totp:        mockTOTP,
				serviceName: tc.serviceName,
				profile:     tc.profile,
				Now:         func() time.Time { return time.Unix(5, 0) },
			}

			if _, err := p.GetCredentials(); err != nil {
				t.Fatalf("GetCredentials() unexpected error: %v", err)
			}

			stderr := restore()
			if !strings.Contains(stderr, tc.wantSubstr) {
				t.Errorf("stderr = %q, want substring %q", stderr, tc.wantSubstr)
			}
		})
	}
}

func stubStdoutIsTerminal(t *testing.T, v bool) {
	t.Helper()
	orig := stdoutIsTerminal
	stdoutIsTerminal = func() bool { return v }
	t.Cleanup(func() { stdoutIsTerminal = orig })
}

func TestProvider_GetCredentials_ClipTipOnlyAtATerminal(t *testing.T) {
	for _, terminal := range []bool{true, false} {
		restore := testutil.RedirectStderr(t)
		stubStdoutIsTerminal(t, terminal)
		p := &Provider{
			store: seeded(t, map[vault.Key]string{totpKey("github", ""): "MYSECRET"}),
			totp: &totpMocks.MockProvider{
				GenerateConsecutiveCodesBytesFunc: func([]byte) (string, string, error) { return "123456", "654321", nil },
			},
			serviceName: "github",
			Now:         func() time.Time { return time.Unix(5, 0) },
		}
		if _, err := p.GetCredentials(); err != nil {
			t.Fatalf("GetCredentials: %v", err)
		}
		stderr := restore()
		const tip = `💡 To copy it instead: sesh --service totp --service-name github --clip`
		if got := strings.Contains(stderr, tip); got != terminal {
			t.Errorf("stdout a terminal: %v; stderr = %q, want the tip: %v", terminal, stderr, terminal)
		}
		if strings.Contains(stderr, "⚠️") {
			t.Errorf("stderr = %q, printing the code isn't a mistake to warn about", stderr)
		}
	}
}

func TestProvider_GetCredentials(t *testing.T) {
	tests := map[string]struct {
		store       vault.Store
		setupTOTP   func(*totpMocks.MockProvider)
		serviceName string
		wantCurrent string
		wantNext    string
		wantErr     bool
	}{
		"successful TOTP generation": {
			store:       seeded(t, map[vault.Key]string{totpKey("github", ""): "MYSECRET"}),
			serviceName: "github",
			setupTOTP: func(m *totpMocks.MockProvider) {
				m.GenerateConsecutiveCodesBytesFunc = func(secret []byte) (string, string, error) {
					if string(secret) == "MYSECRET" {
						return "123456", "654321", nil
					}
					return "", "", fmt.Errorf("unexpected secret")
				}
			},
			wantCurrent: "123456",
			wantNext:    "654321",
		},
		"no such entry": {
			store:       vault.NewMemStore(),
			serviceName: "gitlab",
			setupTOTP:   func(m *totpMocks.MockProvider) {},
			wantErr:     true,
		},
		"store error": {
			store:       failingStore{MemStore: vault.NewMemStore(), err: errors.New("vault locked")},
			serviceName: "gitlab",
			setupTOTP:   func(m *totpMocks.MockProvider) {},
			wantErr:     true,
		},
		"TOTP generation error": {
			store:       seeded(t, map[vault.Key]string{totpKey("bitbucket", ""): "INVALIDSECRET"}),
			serviceName: "bitbucket",
			setupTOTP: func(m *totpMocks.MockProvider) {
				m.GenerateConsecutiveCodesBytesFunc = func(secret []byte) (string, string, error) {
					return "", "", errors.New("invalid secret")
				}
			},
			wantErr: true,
		},
		"empty service name": {
			store:       vault.NewMemStore(),
			serviceName: "",
			setupTOTP:   func(m *totpMocks.MockProvider) {},
			wantErr:     true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			defer testutil.DiscardStderr(t)()

			mockTOTP := &totpMocks.MockProvider{}
			tc.setupTOTP(mockTOTP)

			p := &Provider{
				store:       tc.store,
				totp:        mockTOTP,
				serviceName: tc.serviceName,
			}

			creds, err := p.GetCredentials()
			if tc.wantErr && err == nil {
				t.Error("GetCredentials() expected error but got nil")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("GetCredentials() unexpected error: %v", err)
			}
			if !tc.wantErr {
				if creds.CopyValue != tc.wantCurrent {
					t.Errorf("CopyValue = %v, want %v", creds.CopyValue, tc.wantCurrent)
				}
				if creds.ClipboardDescription != "TOTP code" {
					t.Errorf("ClipboardDescription = %v, want 'TOTP code'", creds.ClipboardDescription)
				}
				if creds.Value != tc.wantCurrent {
					t.Errorf("Value = %q, want the current code %q, for stdout", creds.Value, tc.wantCurrent)
				}
				if strings.Contains(creds.DisplayInfo, tc.wantCurrent) {
					t.Errorf("DisplayInfo = %q, shouldn't repeat the current code printed on stdout", creds.DisplayInfo)
				}
				if !strings.Contains(creds.DisplayInfo, tc.wantNext) {
					t.Error("DisplayInfo should contain next code")
				}
			}
		})
	}
}

func TestProvider_GetCredentials_UsesTheEntrysCodeSettings(t *testing.T) {
	defer testutil.DiscardStderr(t)()
	store := seeded(t, map[vault.Key]string{totpKey("bank", ""): "MYSECRET"})
	want := internalTotp.Params{Algorithm: "SHA256", Digits: 8, Period: 60}
	if err := store.SetSettings(totpKey("bank", ""), vault.Settings{TOTP: want}); err != nil {
		t.Fatal(err)
	}
	var got internalTotp.Params
	p := &Provider{
		store: store,
		totp: &totpMocks.MockProvider{
			GenerateConsecutiveCodesBytesWithParamsFunc: func(_ []byte, params internalTotp.Params) (string, string, error) {
				got = params
				return "12345678", "87654321", nil
			},
		},
		serviceName: "bank",
		Now:         func() time.Time { return time.Unix(5, 0) },
	}
	creds, err := p.GetCredentials()
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Errorf("codes generated with %+v, want the entry's settings %+v", got, want)
	}
	// A 60-second period: 55 seconds left at t=5s.
	if !strings.Contains(creds.DisplayInfo, "Time left: 55s") {
		t.Errorf("DisplayInfo = %q, want the time left in the entry's 60-second period", creds.DisplayInfo)
	}
}

func TestProvider_GetClipboardValue(t *testing.T) {
	tests := map[string]struct {
		store       vault.Store
		setupTOTP   func(*totpMocks.MockProvider)
		checkResult func(*testing.T, provider.Credentials)
		serviceName string
		wantErr     bool
	}{
		"successful clipboard value": {
			store:       seeded(t, map[vault.Key]string{totpKey("github", ""): "MYSECRET"}),
			serviceName: "github",
			setupTOTP: func(m *totpMocks.MockProvider) {
				m.GenerateConsecutiveCodesBytesFunc = func(secret []byte) (string, string, error) {
					if string(secret) == "MYSECRET" {
						return "123456", "654321", nil
					}
					return "", "", fmt.Errorf("unexpected secret")
				}
			},
			checkResult: func(t *testing.T, creds provider.Credentials) {
				if creds.Provider != "totp" {
					t.Errorf("Provider = %v, want 'totp'", creds.Provider)
				}
				if creds.CopyValue != "123456" {
					t.Errorf("CopyValue = %v, want '123456'", creds.CopyValue)
				}
				if !strings.Contains(creds.DisplayInfo, "123456") {
					t.Error("DisplayInfo should contain current code")
				}
				if !strings.Contains(creds.DisplayInfo, "github") {
					t.Error("DisplayInfo should contain service name")
				}
				if !strings.Contains(creds.DisplayInfo, "TOTP code") {
					t.Error("DisplayInfo should contain 'TOTP code'")
				}
				if creds.ClipboardDescription != "TOTP code" {
					t.Errorf("ClipboardDescription = %v, want 'TOTP code'", creds.ClipboardDescription)
				}
			},
		},
		"error getting secret": {
			store:       failingStore{MemStore: vault.NewMemStore(), err: errors.New("vault locked")},
			serviceName: "gitlab",
			setupTOTP:   func(m *totpMocks.MockProvider) {},
			wantErr:     true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			defer testutil.DiscardStderr(t)()

			mockTOTP := &totpMocks.MockProvider{}
			tc.setupTOTP(mockTOTP)

			p := &Provider{
				store:       tc.store,
				totp:        mockTOTP,
				serviceName: tc.serviceName,
			}

			creds, err := p.GetClipboardValue()
			if tc.wantErr && err == nil {
				t.Error("GetClipboardValue() expected error but got nil")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("GetClipboardValue() unexpected error: %v", err)
			}
			if !tc.wantErr && tc.checkResult != nil {
				tc.checkResult(t, creds)
			}
		})
	}
}

func TestProvider_ListEntries(t *testing.T) {
	tests := map[string]struct {
		store        vault.Store
		checkEntries func(*testing.T, []provider.ProviderEntry)
		wantCount    int
		wantErr      bool
	}{
		"successful list": {
			store: seeded(t, map[vault.Key]string{
				totpKey("github", ""):    "s",
				totpKey("gitlab", ""):    "s",
				totpKey("bitbucket", ""): "s",
				// Not a TOTP entry: not listed.
				{Kind: vault.KindPassword, Service: "github"}: "pw",
			}),
			wantCount: 3,
			checkEntries: func(t *testing.T, entries []provider.ProviderEntry) {
				// Listed by key: bitbucket, github, gitlab.
				if entries[1].Name != "github" {
					t.Errorf("entries[1].Name = %v, want 'github'", entries[1].Name)
				}
				if entries[1].Type != "totp" {
					t.Errorf("entries[1].Type = %v, want totp", entries[1].Type)
				}
				if entries[1].ID != "totp/github" {
					t.Errorf("entries[1].ID = %v, want 'totp/github'", entries[1].ID)
				}
			},
		},
		"list with profiles": {
			store: seeded(t, map[vault.Key]string{
				totpKey("github", "work"):     "s",
				totpKey("github", "personal"): "s",
			}),
			wantCount: 2,
			checkEntries: func(t *testing.T, entries []provider.ProviderEntry) {
				if entries[1].Name != "github (work)" {
					t.Errorf("entries[1].Name = %v, want 'github (work)'", entries[1].Name)
				}
				if entries[1].ID != "totp/github/work" {
					t.Errorf("entries[1].ID = %v, want 'totp/github/work'", entries[1].ID)
				}
			},
		},
		"empty list": {
			store:     vault.NewMemStore(),
			wantCount: 0,
		},
		"store error": {
			store:   failingStore{MemStore: vault.NewMemStore(), err: errors.New("vault locked")},
			wantErr: true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			p := &Provider{store: tc.store}

			entries, err := p.ListEntries()
			if tc.wantErr && err == nil {
				t.Error("ListEntries() expected error but got nil")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("ListEntries() unexpected error: %v", err)
			}
			if !tc.wantErr {
				if len(entries) != tc.wantCount {
					t.Errorf("entries count = %d, want %d", len(entries), tc.wantCount)
				}
				if tc.checkEntries != nil {
					tc.checkEntries(t, entries)
				}
			}
		})
	}
}

// The password manager's TOTP entries and --service totp's are the same
// entries in the vault.
func TestProvider_SharesTOTPEntriesWithThePasswordManager(t *testing.T) {
	defer testutil.DiscardStderr(t)()
	store := vault.NewMemStore()
	if err := password.NewManager(store).StoreTOTPSecret("github", "alice", "JBSWY3DPEHPK3PXP"); err != nil {
		t.Fatal(err)
	}

	p := &Provider{
		store: store,
		totp: &totpMocks.MockProvider{
			GenerateConsecutiveCodesBytesFunc: func(secret []byte) (string, string, error) {
				if string(secret) != "JBSWY3DPEHPK3PXP" {
					return "", "", fmt.Errorf("unexpected secret %q", secret)
				}
				return "123456", "654321", nil
			},
		},
		Now: func() time.Time { return time.Unix(5, 0) },
	}
	entries, err := p.ListEntries()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name != "github (alice)" || entries[0].ID != "totp/github/alice" {
		t.Fatalf("ListEntries = %+v, want the password manager's TOTP entry", entries)
	}

	p.serviceName, p.profile = "github", "alice"
	if err := p.ValidateRequest(); err != nil {
		t.Fatalf("ValidateRequest: %v", err)
	}
	creds, err := p.GetClipboardValue()
	if err != nil || creds.CopyValue != "123456" {
		t.Errorf("GetClipboardValue = %q, %v; want the entry's code", creds.CopyValue, err)
	}
}

func TestProvider_DeleteEntry(t *testing.T) {
	gitlab := totpKey("gitlab", "")
	tests := map[string]struct {
		store      vault.Store
		entryID    string
		wantErrMsg string
		wantGone   bool
	}{
		"successful delete": {
			store:    seeded(t, map[vault.Key]string{gitlab: "s"}),
			entryID:  "totp/gitlab",
			wantGone: true,
		},
		"invalid ID format": {
			store:      seeded(t, map[vault.Key]string{gitlab: "s"}),
			entryID:    "invalid-id",
			wantErrMsg: "want kind/service or kind/service/username",
		},
		"missing entry": {
			store:      seeded(t, map[vault.Key]string{gitlab: "s"}),
			entryID:    "totp/github",
			wantErrMsg: "entry not found",
		},
		"store error": {
			store:      failingStore{MemStore: vault.NewMemStore(), err: errors.New("vault locked")},
			entryID:    "totp/gitlab",
			wantErrMsg: "vault locked",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			p := &Provider{store: tc.store}

			err := deleteOne(p, tc.entryID)
			if tc.wantErrMsg == "" {
				if err != nil {
					t.Errorf("DeleteEntry() unexpected error: %v", err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.wantErrMsg) {
				t.Errorf("DeleteEntry() = %v, want it to contain %q", err, tc.wantErrMsg)
			}
			if tc.wantGone {
				if _, err := tc.store.Lookup(gitlab); !errors.Is(err, vault.ErrNotFound) {
					t.Errorf("after DeleteEntry, Lookup = %v; want ErrNotFound", err)
				}
			}
		})
	}
}

func TestProvider_DeleteEntry_RefusesOtherKinds(t *testing.T) {
	pw := vault.Key{Kind: vault.KindPassword, Service: "github"}
	store := seeded(t, map[vault.Key]string{pw: "pw"})
	p := &Provider{store: store}

	err := deleteOne(p, "password/github")
	if wantSub := "isn't a TOTP entry"; err == nil || !strings.Contains(err.Error(), wantSub) {
		t.Errorf("DeleteEntry(password/github) = %v, want it to contain %q", err, wantSub)
	}
	if got, err := store.Get(pw); err != nil || string(got) != "pw" {
		t.Errorf("the password entry = %q, %v; want it untouched", got, err)
	}
}

// lookupFailing reads secrets but not entries' settings.
type lookupFailing struct{ *vault.MemStore }

func (lookupFailing) Lookup(vault.Key) (vault.Entry, error) {
	return vault.Entry{}, errors.New("settings unreadable")
}

func TestProvider_GetCredentials_FailsIfTheCodeSettingsCantBeRead(t *testing.T) {
	store := lookupFailing{vault.NewMemStore()}
	if err := store.Put(vault.Key{Kind: vault.KindTOTP, Service: "github"}, []byte("JBSWY3DPEHPK3PXP")); err != nil {
		t.Fatal(err)
	}
	p := &Provider{store: store, totp: &totpMocks.MockProvider{}, serviceName: "github", Now: time.Now}
	_ = testutil.RedirectStderr(t)
	if _, err := p.GetCredentials(); err == nil || !strings.Contains(err.Error(), "settings unreadable") {
		t.Errorf("GetCredentials = %v, want the settings error rather than a code from the default settings", err)
	}
}

func TestProvider_DeleteEntry_SuggestsANameInAnotherCase(t *testing.T) {
	p := &Provider{store: seeded(t, map[vault.Key]string{totpKey("GitHub", ""): "secret"})}
	err := deleteOne(p, "totp/github")
	if !errors.Is(err, vault.ErrNotFound) || !strings.Contains(err.Error(), "did you mean totp/GitHub? Names are case-sensitive") {
		t.Errorf("DeleteEntry = %v, want not found with the suggestion", err)
	}
}

// deleteOne deletes the entry id names, answering yes when asked.
func deleteOne(p *Provider, id string) error {
	_, err := p.DeleteEntries([]string{id}, func([]string) (bool, error) { return true, nil })
	return err
}
