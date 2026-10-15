// Package screenlock tells whether the computer's screen is locked, so
// sesh's agent can lock with it.
package screenlock

// Locked reports whether the screen of the session sesh runs in is
// locked. known is false where that can't be told: not macOS, built
// without cgo, or outside a login session (over SSH, say).
func Locked() (locked, known bool) { return locked0() }
