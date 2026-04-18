package password

import (
	"testing"

	"github.com/bashhack/sesh/internal/keychain"
	"github.com/bashhack/sesh/internal/keychain/mocks"
	"github.com/bashhack/sesh/internal/password"
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
