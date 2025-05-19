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

// RegisterProvider adds a provider to the registry
func (r *Registry) RegisterProvider(provider ServiceProvider) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.providers[provider.Name()] = provider
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
