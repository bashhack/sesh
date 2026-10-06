// Package shell formats text for a POSIX shell.
package shell

import (
	"regexp"
	"strings"
)

var safe = regexp.MustCompile(`^[A-Za-z0-9@%+=:,./_-]+$`)

// Quote quotes s for a POSIX shell when it needs it, so a command shown to
// the user runs as shown when pasted.
func Quote(s string) string {
	if safe.MatchString(s) {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
