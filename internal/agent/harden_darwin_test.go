//go:build darwin

package agent

// checkPlatformHardening has nothing to read back on macOS: PT_DENY_ATTACH
// leaves no queryable state, so the child only confirms Harden succeeded.
func checkPlatformHardening() error { return nil }
