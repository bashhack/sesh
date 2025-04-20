package mocks

import "github.com/bashhack/sesh/internal/setup"

// MockWizardRunner is a mock implementation of setup.WizardRunner
type MockWizardRunner struct {
	RunFunc func() error
}

// Ensure MockWizardRunner implements setup.WizardRunner interface
var _ setup.WizardRunner = (*MockWizardRunner)(nil)

// Run implements the setup.WizardRunner interface
func (m *MockWizardRunner) Run() error {
	return m.RunFunc()
}
