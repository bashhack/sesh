//go:build linux || darwin

package agent

import (
	"fmt"
	"os"
	"os/exec"
	"testing"

	"golang.org/x/sys/unix"
)

// TestHardenHelperProcess runs Harden in a child process, because
// hardening is process-wide and must not touch the test binary. It is a
// no-op unless SESH_TEST_HARDEN_HELPER=1.
func TestHardenHelperProcess(_ *testing.T) {
	if os.Getenv("SESH_TEST_HARDEN_HELPER") != "1" {
		return
	}
	if err := Harden(); err != nil {
		fmt.Fprintf(os.Stderr, "Harden: %v\n", err)
		os.Exit(3)
	}
	var rl unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_CORE, &rl); err != nil || rl.Cur != 0 || rl.Max != 0 {
		fmt.Fprintf(os.Stderr, "core limit = %+v, err %v; want 0/0\n", rl, err)
		os.Exit(4)
	}
	if err := checkPlatformHardening(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(5)
	}
	os.Exit(0)
}

func TestHarden_AppliesInChildProcess(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=^TestHardenHelperProcess$") //nolint:gosec // re-execs the test binary
	cmd.Env = append(os.Environ(), "SESH_TEST_HARDEN_HELPER=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("hardened child failed: %v\n%s", err, out)
	}
}

func TestMapLockedPage_ReturnsZeroedPage(t *testing.T) {
	b, err := mapLockedPage()
	if err != nil {
		t.Fatalf("mapLockedPage: %v", err)
	}
	if len(b) != os.Getpagesize() {
		t.Fatalf("len = %d, want one page (%d)", len(b), os.Getpagesize())
	}
	for _, c := range b {
		if c != 0 {
			t.Fatal("fresh key page is not zeroed")
		}
	}
	if err := unix.Munlock(b); err != nil {
		t.Fatalf("munlock: %v (page was not locked)", err)
	}
	if err := unix.Munmap(b); err != nil {
		t.Fatal(err)
	}
}
