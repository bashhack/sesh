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
		pipe.Close()
		return err
	}

	if _, err := pipe.Write([]byte(text)); err != nil {
		pipe.Close()
		cmd.Wait()
		return err
	}

	if err := pipe.Close(); err != nil {
		cmd.Wait()
		return err
	}

	return cmd.Wait()
}
