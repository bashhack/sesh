package provider

import (
	"errors"
	"strings"
	"testing"
)

// mockProvider implements ServiceProvider for testing
type mockProvider struct {
	name        string
	description string
}

func (p *mockProvider) Name() string {
	return p.name
}

func (p *mockProvider) Description() string {
	return p.description
}

func (p *mockProvider) SetupFlags(fs FlagSet) error {
	return nil
}

func (p *mockProvider) GetCredentials() (Credentials, error) {
	if p.name == "error" {
		return Credentials{}, errors.New("mock error")
	}
	return Credentials{Provider: p.name}, nil
}

func (p *mockProvider) ListEntries() ([]ProviderEntry, error) {
	if p.name == "error" {
		return nil, errors.New("mock error")
	}
	return []ProviderEntry{
		{
			Name:        "test-entry",
			Description: "Test entry",
			ID:          "test-id",
		},
	}, nil
}

func (p *mockProvider) DeleteEntry(id string) error {
	if p.name == "error" {
		return errors.New("mock error")
	}
	return nil
}

func (p *mockProvider) GetClipboardValue() (Credentials, error) {
	if p.name == "error" {
		return Credentials{}, errors.New("mock error")
	}
	return Credentials{Provider: p.name, CopyValue: "mock-clipboard-value"}, nil
}

func (p *mockProvider) GetSetupHandler() interface{} {
	return nil
}

func (p *mockProvider) ValidateRequest() error {
	if p.name == "error" {
		return errors.New("mock validation error")
	}
	return nil
}

func (p *mockProvider) GetFlagInfo() []FlagInfo {
	return []FlagInfo{
		{
			Name:        "test-flag",
			Type:        "string",
			Description: "Test flag",
			Required:    false,
		},
	}
}

func TestRegistry_GetProvider(t *testing.T) {
	tests := map[string]struct {
		register []string
		lookup   string
		wantErr  bool
	}{
		"registered provider found": {
			register: []string{"aws", "totp"},
			lookup:   "aws",
		},
		"second registered provider found": {
			register: []string{"aws", "totp"},
			lookup:   "totp",
		},
		"unknown provider returns error": {
			register: []string{"aws"},
			lookup:   "unknown",
			wantErr:  true,
		},
		"empty registry returns error": {
			lookup:  "aws",
			wantErr: true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			registry := NewRegistry()
			for _, n := range tc.register {
				registry.RegisterProvider(&mockProvider{name: n, description: n + " provider"})
			}

			p, err := registry.GetProvider(tc.lookup)
			if tc.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if p.Name() != tc.lookup {
				t.Errorf("Name() = %q, want %q", p.Name(), tc.lookup)
			}
		})
	}
}

func TestRegistry_RegisterProvider_PanicsOnNil(t *testing.T) {
	registry := NewRegistry()

	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected panic on nil provider, got none")
		}
		msg, ok := r.(string)
		if !ok || !strings.Contains(msg, "nil provider") {
			t.Errorf("unexpected panic value: %v", r)
		}
	}()

	registry.RegisterProvider(nil)
}

func TestRegistry_RegisterProvider_PanicsOnDuplicate(t *testing.T) {
	registry := NewRegistry()
	registry.RegisterProvider(&mockProvider{name: "aws", description: "original"})

	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected panic on duplicate registration, got none")
		}
		msg, ok := r.(string)
		if !ok || !strings.Contains(msg, "already registered") {
			t.Errorf("unexpected panic value: %v", r)
		}
	}()

	registry.RegisterProvider(&mockProvider{name: "aws", description: "duplicate"})
}

func TestRegistry_ListProviders(t *testing.T) {
	tests := map[string]struct {
		register  []string
		wantNames []string
	}{
		"empty registry": {
			wantNames: nil,
		},
		"single provider": {
			register:  []string{"aws"},
			wantNames: []string{"aws"},
		},
		"multiple providers sorted by name": {
			register:  []string{"totp", "aws", "gcp"},
			wantNames: []string{"aws", "gcp", "totp"},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			registry := NewRegistry()
			for _, n := range tc.register {
				registry.RegisterProvider(&mockProvider{name: n, description: n + " provider"})
			}

			providers := registry.ListProviders()
			if len(providers) != len(tc.wantNames) {
				t.Fatalf("len(ListProviders()) = %d, want %d", len(providers), len(tc.wantNames))
			}

			for i, p := range providers {
				if p.Name() != tc.wantNames[i] {
					t.Errorf("providers[%d].Name() = %q, want %q", i, p.Name(), tc.wantNames[i])
				}
			}
		})
	}
}
