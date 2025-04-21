package mocks

import "github.com/bashhack/sesh/internal/setup"

// MockWizardRunner is a mock implementation of setup.WizardRunner
type MockWizardRunner struct {
	RunFunc           func() error
	RunForServiceFunc func(serviceName string) error
}

// Ensure MockWizardRunner implements setup.WizardRunner interface
var _ setup.WizardRunner = (*MockWizardRunner)(nil)

// Run implements the setup.WizardRunner interface
func (m *MockWizardRunner) Run() error {
	if m.RunFunc != nil {
		return m.RunFunc()
	}
	return nil
}

// RunForService implements the setup.WizardRunner interface
func (m *MockWizardRunner) RunForService(serviceName string) error {
	if m.RunForServiceFunc != nil {
		return m.RunForServiceFunc(serviceName)
	}
	return nil
}