// Package clipboard provides system clipboard access for copying TOTP codes.
package clipboard

import (
	"fmt"
	"os/exec"
	"runtime"
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
