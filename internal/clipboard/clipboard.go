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
	case "linux":
		return copyLinux(text)
	case "windows":
		return copyWindows(text)
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

// copyLinux copies text to clipboard on Linux
func copyLinux(text string) error {
	// Try xclip first
	cmd := exec.Command("xclip", "-selection", "clipboard")
	pipe, err := cmd.StdinPipe()
	if err == nil {
		if err := cmd.Start(); err == nil {
			if _, err := pipe.Write([]byte(text)); err == nil {
				if err := pipe.Close(); err == nil {
					return cmd.Wait()
				}
			}
		}
	}
	
	// Try xsel if xclip failed
	cmd = exec.Command("xsel", "--clipboard", "--input")
	pipe, err = cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("no clipboard utility available: install xclip or xsel")
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

// copyWindows copies text to clipboard on Windows
func copyWindows(text string) error {
	cmd := exec.Command("powershell", "-command", "Set-Clipboard", "-Value", text)
	return cmd.Run()
}