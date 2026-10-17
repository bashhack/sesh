//go:build !darwin

package syncfolder

import "syscall"

// dataless is false: only macOS keeps a file's data in the cloud this way.
func dataless(*syscall.Stat_t) bool { return false }
