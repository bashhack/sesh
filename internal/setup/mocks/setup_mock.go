package mocks

// WizardRunner interface was moved out of the setup package

// MockWizardRunner is a mock implementation of setup.WizardRunner
type MockWizardRunner struct {
	RunFunc           func() error
	RunForServiceFunc func(serviceName string) error
}

// Ensure MockWizardRunner implements a WizardRunner interface
// Note: This interface may not be defined in setup package anymore

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
