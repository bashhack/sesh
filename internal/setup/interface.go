package setup

import (
	"fmt"
)

// SetupHandler defines a handler for a specific service setup
type SetupHandler interface {
	ServiceName() string
	Setup() error
}

// SetupService is the main service for setting up credentials
type SetupService interface {
	// RegisterHandler registers a setup handler for a service
	RegisterHandler(handler SetupHandler)

	// SetupService initiates the setup process for a specific service
	SetupService(serviceName string) error

	// GetAvailableServices returns a list of services that can be set up
	GetAvailableServices() []string
}

// setupServiceImpl is the implementation of SetupService
type setupServiceImpl struct {
	handlers map[string]SetupHandler
}

// NewSetupService creates a new SetupService
func NewSetupService() SetupService {
	return &setupServiceImpl{handlers: make(map[string]SetupHandler)}
}

// RegisterHandler registers a setup handler for a service
func (s *setupServiceImpl) RegisterHandler(handler SetupHandler) {
	s.handlers[handler.ServiceName()] = handler
}

// SetupService initiates the setup process for a specific service
func (s *setupServiceImpl) SetupService(serviceName string) error {
	handler, exists := s.handlers[serviceName]
	if !exists {
		return fmt.Errorf("no setup handler registered for service: %s", serviceName)
	}

	return handler.Setup()
}

// GetAvailableServices returns a list of services that can be set up
func (s *setupServiceImpl) GetAvailableServices() []string {
	services := make([]string, 0, len(s.handlers))
	for service := range s.handlers {
		services = append(services, service)
	}
	return services
}
