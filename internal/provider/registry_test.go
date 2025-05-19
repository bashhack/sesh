package provider

import (
	"errors"
	"flag"
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

func (p *mockProvider) SetupFlags(fs *flag.FlagSet) {
	// Do nothing for testing
}

func (p *mockProvider) Setup() error {
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

func TestRegistry_RegisterProvider(t *testing.T) {
	registry := NewRegistry()

	provider1 := &mockProvider{name: "test1", description: "Test Provider 1"}
	provider2 := &mockProvider{name: "test2", description: "Test Provider 2"}

	// Register providers
	registry.RegisterProvider(provider1)
	registry.RegisterProvider(provider2)

	// Test GetProvider
	p1, err := registry.GetProvider("test1")
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if p1.Name() != "test1" {
		t.Errorf("Expected provider name 'test1', got '%s'", p1.Name())
	}

	p2, err := registry.GetProvider("test2")
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if p2.Name() != "test2" {
		t.Errorf("Expected provider name 'test2', got '%s'", p2.Name())
	}

	// Test GetProvider for unknown provider
	_, err = registry.GetProvider("unknown")
	if err == nil {
		t.Error("Expected error for unknown provider, got nil")
	}
}

func TestRegistry_ListProviders(t *testing.T) {
	registry := NewRegistry()

	// Empty registry
	providers := registry.ListProviders()
	if len(providers) != 0 {
		t.Errorf("Expected empty list, got %d providers", len(providers))
	}

	// Add providers
	provider1 := &mockProvider{name: "test1", description: "Test Provider 1"}
	provider2 := &mockProvider{name: "test2", description: "Test Provider 2"}

	registry.RegisterProvider(provider1)
	registry.RegisterProvider(provider2)

	// List providers
	providers = registry.ListProviders()
	if len(providers) != 2 {
		t.Errorf("Expected 2 providers, got %d", len(providers))
	}

	// Check if providers are in the list
	foundProvider1 := false
	foundProvider2 := false

	for _, p := range providers {
		if p.Name() == "test1" {
			foundProvider1 = true
		}
		if p.Name() == "test2" {
			foundProvider2 = true
		}
	}

	if !foundProvider1 {
		t.Error("Provider 'test1' not found in list")
	}
	if !foundProvider2 {
		t.Error("Provider 'test2' not found in list")
	}
}
