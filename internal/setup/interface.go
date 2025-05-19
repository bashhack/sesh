package setup

import (
	"github.com/bashhack/sesh/internal/keychain"
)

// WizardRunner defines an interface for running the setup wizard
type WizardRunner interface {
	Run() error
	RunForService(serviceName string) error
}

// DefaultWizardRunner is the default implementation of WizardRunner
type DefaultWizardRunner struct {
	KeychainProvider keychain.Provider
}

// NewDefaultWizardRunner creates a new DefaultWizardRunner with the given keychain provider
func NewDefaultWizardRunner(provider keychain.Provider) *DefaultWizardRunner {
	return &DefaultWizardRunner{
		KeychainProvider: provider,
	}
}

// Run implements WizardRunner interface
func (w *DefaultWizardRunner) Run() error {
	return w.RunForService("aws")
}

// RunForService runs the setup wizard for a specific service
func (w *DefaultWizardRunner) RunForService(serviceName string) error {
	switch serviceName {
	case "aws":
		return setupAWSWithProvider(w.KeychainProvider)
	case "totp":
		return setupGenericTOTPWithProvider(w.KeychainProvider)
	default:
		return nil
	}
}
