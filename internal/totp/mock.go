package totp

// MockGenerateConsecutiveCodes allows tests to override the behavior of GenerateConsecutiveCodes
var MockGenerateConsecutiveCodes struct {
	// CurrentCode is the first code to return
	CurrentCode string
	// NextCode is the second code to return
	NextCode string
	// Error is the error to return
	Error error
	// Enabled indicates whether the mock should be used
	Enabled bool
}

// ResetMock resets the mock to its default state
func ResetMock() {
	MockGenerateConsecutiveCodes.CurrentCode = ""
	MockGenerateConsecutiveCodes.NextCode = ""
	MockGenerateConsecutiveCodes.Error = nil
	MockGenerateConsecutiveCodes.Enabled = false
}
