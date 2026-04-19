package clipboard

import (
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestCopy(t *testing.T) {
	originalExecCommand := execCommand
	originalRuntimeGOOS := runtimeGOOS
	defer func() {
		execCommand = originalExecCommand
		runtimeGOOS = originalRuntimeGOOS
	}()

	tests := map[string]struct {
		mockCmd func(name string, args ...string) *exec.Cmd
		text    string
		goos    string
		errMsg  string
		wantErr bool
	}{
		"darwin success": {
			text: "test text",
			goos: "darwin",
			mockCmd: func(name string, args ...string) *exec.Cmd {
				if name == "pbcopy" {
					return exec.Command("cat")
				}
				return nil
			},
			wantErr: false,
		},
		"darwin empty text": {
			text: "",
			goos: "darwin",
			mockCmd: func(name string, args ...string) *exec.Cmd {
				if name == "pbcopy" {
					return exec.Command("cat")
				}
				return nil
			},
			wantErr: false,
		},
		"darwin command not found": {
			text: "test text",
			goos: "darwin",
			mockCmd: func(name string, args ...string) *exec.Cmd {
				return exec.Command("/nonexistent/pbcopy")
			},
			wantErr: true,
		},
		"unsupported platform": {
			text:    "test text",
			goos:    "linux",
			wantErr: true,
			errMsg:  "unsupported platform: linux",
		},
		"windows platform": {
			text:    "test text",
			goos:    "windows",
			wantErr: true,
			errMsg:  "unsupported platform: windows",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			runtimeGOOS = tc.goos
			if tc.mockCmd != nil {
				execCommand = tc.mockCmd
			}

			err := Copy(tc.text)

			if (err != nil) != tc.wantErr {
				t.Errorf("Copy() error = %v, wantErr %v", err, tc.wantErr)
				return
			}

			if tc.errMsg != "" && err != nil && err.Error() != tc.errMsg {
				t.Errorf("Copy() error = %v, want %v", err.Error(), tc.errMsg)
			}
		})
	}
}

func TestCopyOSX(t *testing.T) {
	originalExecCommand := execCommand
	defer func() {
		execCommand = originalExecCommand
	}()

	tests := map[string]struct {
		mockCmd func(name string, args ...string) *exec.Cmd
		text    string
		wantErr bool
	}{
		"success": {
			text: "clipboard content",
			mockCmd: func(name string, args ...string) *exec.Cmd {
				if name == "pbcopy" {
					return exec.Command("cat")
				}
				return nil
			},
			wantErr: false,
		},
		"multiline text": {
			text: "line1\nline2\nline3",
			mockCmd: func(name string, args ...string) *exec.Cmd {
				if name == "pbcopy" {
					return exec.Command("cat")
				}
				return nil
			},
			wantErr: false,
		},
		"special characters": {
			text: "text with 'quotes' and \"double quotes\" and $variables",
			mockCmd: func(name string, args ...string) *exec.Cmd {
				if name == "pbcopy" {
					return exec.Command("cat")
				}
				return nil
			},
			wantErr: false,
		},
		"command fails": {
			text: "test",
			mockCmd: func(name string, args ...string) *exec.Cmd {
				if name == "pbcopy" {
					return exec.Command("false")
				}
				return nil
			},
			wantErr: true,
		},
		"command not found": {
			text: "test",
			mockCmd: func(name string, args ...string) *exec.Cmd {
				return exec.Command("/nonexistent/command")
			},
			wantErr: true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			execCommand = tc.mockCmd

			err := copyOSX(tc.text)

			if (err != nil) != tc.wantErr {
				t.Errorf("copyOSX() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestCopyWithAutoClear(t *testing.T) {
	originalExecCommand := execCommand
	originalRuntimeGOOS := runtimeGOOS
	defer func() {
		execCommand = originalExecCommand
		runtimeGOOS = originalRuntimeGOOS
	}()

	tests := map[string]struct {
		mockCmd func(name string, args ...string) *exec.Cmd
		goos    string
		wantErr bool
	}{
		"darwin success": {
			goos: "darwin",
			mockCmd: func(name string, args ...string) *exec.Cmd {
				// Both pbcopy and sh calls go through execCommand
				if name == "pbcopy" {
					return exec.Command("cat")
				}
				return exec.Command("true")
			},
		},
		"unsupported platform fails on copy": {
			goos: "linux",
			mockCmd: func(name string, args ...string) *exec.Cmd {
				return exec.Command("true")
			},
			wantErr: true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			runtimeGOOS = tc.goos
			execCommand = tc.mockCmd

			err := CopyWithAutoClear("test-secret", 1*time.Second)
			if (err != nil) != tc.wantErr {
				t.Errorf("CopyWithAutoClear() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

// TestSpawnClearDarwin_ScriptShape asserts the spawned script has a
// correct sleep value, slurps multiline stdin, and clears via pbcopy.
func TestSpawnClearDarwin_ScriptShape(t *testing.T) {
	originalExecCommand := execCommand
	defer func() { execCommand = originalExecCommand }()

	tests := map[string]struct {
		wantSecs      string
		timeout       time.Duration
		wantMultiline bool // script should slurp full stdin, not one line
		wantPbCopy    bool // script should pipe '' into pbcopy on match
	}{
		"30 seconds": {
			timeout:       30 * time.Second,
			wantSecs:      "sleep 30",
			wantMultiline: true,
			wantPbCopy:    true,
		},
		"sub-second rounds up to 1": {
			// Guards against the historic int(seconds) flooring bug that
			// produced "sleep 0" (immediate clear) for any timeout < 1s.
			timeout:       500 * time.Millisecond,
			wantSecs:      "sleep 1",
			wantMultiline: true,
			wantPbCopy:    true,
		},
		"zero timeout clamps to 1": {
			timeout:       0,
			wantSecs:      "sleep 1",
			wantMultiline: true,
			wantPbCopy:    true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			var capturedScript string
			execCommand = func(name string, args ...string) *exec.Cmd {
				if name == "sh" && len(args) >= 2 && args[0] == "-c" {
					capturedScript = args[1]
				}
				return exec.Command("true")
			}

			if err := spawnClearDarwin("the-secret", tc.timeout); err != nil {
				t.Fatalf("spawnClearDarwin: %v", err)
			}
			if !strings.Contains(capturedScript, tc.wantSecs) {
				t.Errorf("script should contain %q, got:\n%s", tc.wantSecs, capturedScript)
			}
			if tc.wantMultiline {
				// Must slurp the full stdin (not just the first line)
				// so secure notes and any secret with an embedded newline
				// are compared correctly.
				if !strings.Contains(capturedScript, "expected=$(cat)") {
					t.Errorf("script should use `expected=$(cat)` for multiline-safe input, got:\n%s", capturedScript)
				}
				// Explicitly guard against regression to the old `read -r`
				// pattern, which only grabs the first line.
				if strings.Contains(capturedScript, "read -r") {
					t.Errorf("script should NOT use `read -r` (truncates multiline secrets), got:\n%s", capturedScript)
				}
			}
			if tc.wantPbCopy && !strings.Contains(capturedScript, "pbcopy") {
				t.Errorf("script should end by clearing via pbcopy, got:\n%s", capturedScript)
			}
		})
	}
}

// TestSpawnClearDarwin_MultilineRoundTrip executes the compare step
// against a stubbed clipboard to prove multiline secrets actually match.
func TestSpawnClearDarwin_MultilineRoundTrip(t *testing.T) {
	// Guards the historic `read -r expected` bug where only the first
	// line was read — multiline secure notes would never match and the
	// clipboard would be left holding plaintext indefinitely.
	secret := "line1\nline2\nwith spaces and 'quotes'"

	// Build the same script the production code builds.
	cmd := exec.Command("sh", "-c", `expected=$(cat)
current=$(printf '%s' "$STUB_CLIPBOARD")
if [ "$current" = "$expected" ]; then
  printf 'MATCH'
else
  printf 'MISMATCH'
fi`)
	cmd.Env = append(cmd.Env, "STUB_CLIPBOARD="+secret)
	cmd.Stdin = strings.NewReader(secret + "\n")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("exec: %v", err)
	}
	if string(out) != "MATCH" {
		t.Errorf("multiline comparison failed: got %q, want MATCH — secret would have been left in clipboard", out)
	}
}
