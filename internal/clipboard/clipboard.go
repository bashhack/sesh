// Package clipboard provides system clipboard access for copying and clearing secrets.
package clipboard

import (
	"fmt"
	"math"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

var (
	execCommand = exec.Command
	runtimeGOOS = runtime.GOOS
)

// Copy copies text to the clipboard and returns an error if unsuccessful
func Copy(text string) error {
	switch runtimeGOOS {
	case "darwin":
		return copyOSX(text)
	default:
		return fmt.Errorf("unsupported platform: %s", runtimeGOOS)
	}
}

// CopyWithAutoClear copies text to the clipboard and spawns a detached
// background process that clears it after the given timeout — but only
// if the clipboard still contains the original value. This is safe even
// though the sesh process exits immediately after the copy.
func CopyWithAutoClear(text string, timeout time.Duration) error {
	if err := Copy(text); err != nil {
		return err
	}

	switch runtimeGOOS {
	case "darwin":
		return spawnClearDarwin(text, timeout)
	default:
		// On unsupported platforms, the copy already succeeded — just skip auto-clear.
		return nil
	}
}

// spawnClearDarwin launches a detached sh process that sleeps, checks if the
// clipboard still holds the original value, and clears it if so.
func spawnClearDarwin(original string, timeout time.Duration) error {
	// Round up so sub-second timeouts don't truncate to "sleep 0" (which
	// would clear the clipboard immediately). Clamp to a 1-second floor.
	seconds := strconv.Itoa(max(int(math.Ceil(timeout.Seconds())), 1))

	// Shell script:
	//  1. Slurp the expected value from stdin (must be multiline-safe —
	//     secure notes and any secret containing a newline need the full
	//     value compared, not just the first line).
	//  2. Sleep for the timeout.
	//  3. Compare the clipboard to the expected value.
	//  4. If they match, overwrite the clipboard with an empty string.
	script := `expected=$(cat)
sleep ` + seconds + `
current=$(pbpaste)
if [ "$current" = "$expected" ]; then
  printf '' | pbcopy
fi`

	cmd := execCommand("sh", "-c", script)
	cmd.Stdin = strings.NewReader(original + "\n")

	// Detach the child process so it survives after sesh exits.
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
	}

	if err := cmd.Start(); err != nil {
		// Non-fatal: the copy succeeded, auto-clear just won't happen.
		// Surface it so the user knows why the clipboard won't clear.
		fmt.Fprintf(os.Stderr, "clipboard auto-clear: failed to start: %v\n", err)
		return nil
	}

	// Release the Go-side process handle. sesh typically exits before the
	// child's `sleep N` returns, so Wait() here would rarely run anyway —
	// the child is forked into its own process group (Setpgid above) and is
	// reparented to PID 1 on sesh's exit, which reaps it.
	if err := cmd.Process.Release(); err != nil {
		fmt.Fprintf(os.Stderr, "clipboard auto-clear: failed to release process handle: %v\n", err)
	}

	return nil
}

// copyOSX copies text to clipboard on macOS
func copyOSX(text string) error {
	cmd := execCommand("pbcopy")
	pipe, err := cmd.StdinPipe()
	if err != nil {
		return err
	}

	if err := cmd.Start(); err != nil {
		if closeErr := pipe.Close(); closeErr != nil {
			return fmt.Errorf("start failed: %w (and pipe close failed: %v)", err, closeErr)
		}
		return err
	}

	if _, err := pipe.Write([]byte(text)); err != nil {
		closeErr := pipe.Close()
		waitErr := cmd.Wait()
		if closeErr != nil && waitErr != nil {
			return fmt.Errorf("write failed: %w (pipe close failed: %v; wait failed: %v)", err, closeErr, waitErr)
		}
		if closeErr != nil {
			return fmt.Errorf("write failed: %w (and pipe close failed: %v)", err, closeErr)
		}
		if waitErr != nil {
			return fmt.Errorf("write failed: %w (and wait failed: %v)", err, waitErr)
		}
		return err
	}

	if err := pipe.Close(); err != nil {
		if waitErr := cmd.Wait(); waitErr != nil {
			return fmt.Errorf("pipe close failed: %w (and wait failed: %v)", err, waitErr)
		}
		return err
	}

	return cmd.Wait()
}
