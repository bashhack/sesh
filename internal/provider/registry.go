package provider

import (
	"fmt"
	"sync"
)

// Registry manages available service providers
type Registry struct {
	providers map[string]ServiceProvider
	mu        sync.RWMutex
}

// NewRegistry creates a new provider registry
func NewRegistry() *Registry {
	return &Registry{
		providers: make(map[string]ServiceProvider),
	}
}

// RegisterProvider adds a provider to the registry.
// Panics if a provider with the same name is already registered.
func (r *Registry) RegisterProvider(provider ServiceProvider) {
	if provider == nil {
		panic("cannot register nil provider")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	name := provider.Name()
	if _, exists := r.providers[name]; exists {
		panic(fmt.Sprintf("provider %q already registered", name))
	}
	r.providers[name] = provider
}

// GetProvider returns a provider by name
func (r *Registry) GetProvider(name string) (ServiceProvider, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	p, ok := r.providers[name]
	if !ok {
		return nil, fmt.Errorf("provider %q not found", name)
	}

	return p, nil
}

// ListProviders returns all registered providers
func (r *Registry) ListProviders() []ServiceProvider {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]ServiceProvider, 0, len(r.providers))
	for _, p := range r.providers {
		result = append(result, p)
	}

	return result
}
