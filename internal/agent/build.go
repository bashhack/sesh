package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"sync"
)

// Build identifies the program this process runs: the hex SHA-256 of its
// executable, read once. Two processes with different builds are
// different sesh versions, whatever their version strings say. "" means
// the executable couldn't be read, which turns the comparison off.
func Build() string { return thisBuild() }

// thisBuild is Build's implementation. Tests replace it to fake a
// different build.
var thisBuild = sync.OnceValue(executableHash)

func executableHash() string {
	path, err := os.Executable()
	if err != nil {
		return ""
	}
	f, err := os.Open(path) //nolint:gosec // this process's own executable
	if err != nil {
		return ""
	}
	defer closeOrLog(f, "executable after hashing")
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}

// otherBuild reports whether an agent that reported build agentBuild runs
// a different program from this one. An agent that reports nothing
// predates build reporting, so it counts as different.
func otherBuild(agentBuild string) bool {
	mine := thisBuild()
	return mine != "" && agentBuild != mine
}

// shortBuild is the first 12 hex digits of a build, for messages.
func shortBuild(b string) string {
	if b == "" {
		return "unknown"
	}
	return b[:min(12, len(b))]
}
