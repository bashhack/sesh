//go:build race

package vaultsync

// raceDetector is set when the tests run with -race, which makes the
// heaviest ones too slow to run: they run in the build without it.
const raceDetector = true
