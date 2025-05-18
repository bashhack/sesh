package clipboard

import (
	"fmt"
	"os/exec"
	"runtime"
)

// Copy copies text to the clipboard and returns an error if unsuccessful
func Copy(text string) error {
	switch runtime.GOOS {
	case "darwin":
		return copyOSX(text)
	default:
		return fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
}

// copyOSX copies text to clipboard on macOS
func copyOSX(text string) error {
	cmd := exec.Command("pbcopy")
	pipe, err := cmd.StdinPipe()
	if err != nil {
		return err
	}

	if err := cmd.Start(); err != nil {
		return err
	}

	if _, err := pipe.Write([]byte(text)); err != nil {
		return err
	}

	if err := pipe.Close(); err != nil {
		return err
	}

	return cmd.Wait()
}
