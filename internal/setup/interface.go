package setup

// WizardRunner defines an interface for running the setup wizard
type WizardRunner interface {
	Run() error
	RunForService(serviceName string) error
}

// DefaultWizardRunner is the default implementation of WizardRunner
type DefaultWizardRunner struct{}

// Run implements WizardRunner interface
func (w DefaultWizardRunner) Run() error {
	RunWizard() // Since RunWizard has no return value, just call it...
	return nil  // ...assume it succeeded if it didn't call os.Exit
}

// RunForService runs the setup wizard for a specific service
func (w DefaultWizardRunner) RunForService(serviceName string) error {
	RunWizardForService(serviceName)
	return nil
}