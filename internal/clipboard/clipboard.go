// Package clipboard provides system clipboard access for copying and clearing secrets.
package clipboard

import (
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"
)

var (
	execCommand = exec.Command
	runtimeGOOS = runtime.GOOS
	lookPath    = exec.LookPath
	getenv      = os.Getenv
)

// Tool is how sesh reaches the clipboard on this system: a command that
// copies its stdin, and shell commands that print and empty the clipboard,
// for clearing it later.
type Tool struct {
	// Name is the program, as messages and sesh doctor show it.
	Name  string
	paste string
	clear string
	copy  []string
}

// MissingToolError is a Linux desktop session with no clipboard tool
// installed for it.
type MissingToolError struct {
	// Install names what to install, as "xclip or xsel".
	Install string
}

func (e *MissingToolError) Error() string {
	return "no clipboard tool found: install " + e.Install
}

// ErrNoDisplay is a Linux session with no desktop to copy to, as over SSH.
var ErrNoDisplay = errors.New("there's no desktop session to copy to here (neither WAYLAND_DISPLAY nor DISPLAY is set), as over SSH")

// Find returns the clipboard tool for this system: pbcopy on macOS; on
// Linux, wl-copy under Wayland, or xclip or xsel under X11. An error says
// what's missing.
func Find() (Tool, error) {
	switch runtimeGOOS {
	case "darwin":
		return Tool{Name: "pbcopy", copy: []string{"pbcopy"}, paste: "pbpaste", clear: "printf '' | pbcopy"}, nil
	case "linux":
		return findLinux()
	}
	return Tool{}, fmt.Errorf("unsupported platform: %s", runtimeGOOS)
}

func findLinux() (Tool, error) {
	has := func(names ...string) bool {
		for _, n := range names {
			if _, err := lookPath(n); err != nil {
				return false
			}
		}
		return true
	}
	wayland, x11 := getenv("WAYLAND_DISPLAY") != "", getenv("DISPLAY") != ""
	switch {
	case wayland && has("wl-copy", "wl-paste"):
		return Tool{Name: "wl-copy", copy: []string{"wl-copy"}, paste: "wl-paste --no-newline", clear: "wl-copy --clear"}, nil
	case x11 && has("xclip"):
		return Tool{Name: "xclip", copy: []string{"xclip", "-selection", "clipboard"}, paste: "xclip -selection clipboard -o", clear: "printf '' | xclip -selection clipboard"}, nil
	case x11 && has("xsel"):
		return Tool{Name: "xsel", copy: []string{"xsel", "--clipboard", "--input"}, paste: "xsel --clipboard --output", clear: "xsel --clipboard --clear"}, nil
	case wayland && x11:
		return Tool{}, &MissingToolError{Install: "wl-clipboard (wl-copy), or xclip or xsel"}
	case wayland:
		return Tool{}, &MissingToolError{Install: "wl-clipboard (wl-copy)"}
	case x11:
		return Tool{}, &MissingToolError{Install: "xclip or xsel"}
	}
	return Tool{}, ErrNoDisplay
}

// Copy copies text to the clipboard and returns an error if unsuccessful
func Copy(text string) error {
	tool, err := Find()
	if err != nil {
		return err
	}
	return copyWith(tool, text)
}

// CopyWithAutoClear copies text to the clipboard and spawns a detached
// background process that clears it after the given timeout — but only
// if the clipboard still contains the original value. This is safe even
// though the sesh process exits immediately after the copy.
func CopyWithAutoClear(text string, timeout time.Duration) error {
	tool, err := Find()
	if err != nil {
		return err
	}
	if err := copyWith(tool, text); err != nil {
		return err
	}
	return spawnClear(tool, text, timeout)
}

// spawnClear launches a detached sh process that sleeps, checks if the
// clipboard still holds the original value, and clears it if so.
func spawnClear(tool Tool, original string, timeout time.Duration) error {
	// Round up so sub-second timeouts don't truncate to "sleep 0" (which
	// would clear the clipboard immediately). Clamp to a 1-second floor.
	seconds := strconv.Itoa(max(int(math.Ceil(timeout.Seconds())), 1))

	// Shell script:
	//  1. Slurp the expected value from stdin (must be multiline-safe —
	//     secure notes and any secret containing a newline need the full
	//     value compared, not just the first line).
	//  2. Sleep for the timeout.
	//  3. Compare the clipboard to the expected value.
	//  4. If they match, empty the clipboard.
	script := `expected=$(cat)
sleep ` + seconds + `
current=$(` + tool.paste + ` 2>/dev/null)
if [ "$current" = "$expected" ]; then
  ` + tool.clear + `
fi`
	cmd := execCommand("sh", "-c", script)
	detach(cmd)
	// Its own process group, so it survives after sesh exits.
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		fmt.Fprintf(os.Stderr, "clipboard auto-clear: failed to start: %v\n", err)
		return nil
	}

	if err := cmd.Start(); err != nil {
		// Non-fatal: the copy succeeded, auto-clear just won't happen.
		// Surface it so the user knows why the clipboard won't clear.
		fmt.Fprintf(os.Stderr, "clipboard auto-clear: failed to start: %v\n", err)
		return nil
	}

	// The secret is written before sesh lets the script go: sesh exits
	// right after, and a write left to exec's background copy could be
	// lost, leaving the script nothing to compare and the clipboard never
	// cleared. The trailing newline ends $(cat); $(…) strips it, so the
	// script compares the value itself. The script reads at once, so this
	// doesn't wait on the sleep.
	_, werr := io.WriteString(stdin, original+"\n")
	if cerr := stdin.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		fmt.Fprintf(os.Stderr, "clipboard auto-clear: failed to pass the value: %v\n", werr)
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

// detach sets up a command that may outlive sesh: the copy tools on Linux
// stay running to serve the clipboard, and the clearing script sleeps. It
// runs from "/", so it holds no folder of the user's, and without
// SESH_MASTER_PASSWORD, which would stay readable in its environment.
func detach(cmd *exec.Cmd) {
	cmd.Dir = "/"
	env := os.Environ()
	cmd.Env = slices.DeleteFunc(env, func(kv string) bool {
		return strings.HasPrefix(kv, "SESH_MASTER_PASSWORD=")
	})
}

// toolError adds what the tool said, if anything, to its failure.
func toolError(tool Tool, err error, stderr *os.File) error {
	if stderr == nil {
		return err
	}
	b := make([]byte, 512)
	n, _ := stderr.ReadAt(b, 0) //nolint:errcheck // what was read is all there is to add
	if msg := strings.TrimSpace(string(b[:n])); msg != "" {
		return fmt.Errorf("%s: %w: %s", tool.Name, err, msg)
	}
	return fmt.Errorf("%s: %w", tool.Name, err)
}

// copyWith copies text to the clipboard with tool. The tool's error
// output goes to a temporary file, not a pipe: xclip and wl-copy leave a
// process running that holds it, and Wait would wait for that to end.
func copyWith(tool Tool, text string) (err error) {
	cmd := execCommand(tool.copy[0], tool.copy[1:]...)
	detach(cmd)
	stderr, ferr := os.CreateTemp("", "sesh-clipboard-*")
	if ferr == nil {
		cmd.Stderr = stderr
		defer func() {
			if err != nil {
				err = toolError(tool, err, stderr)
			}
			stderr.Close()           //nolint:errcheck,gosec // only read from
			os.Remove(stderr.Name()) //nolint:errcheck,gosec // a temporary file
		}()
	}
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
