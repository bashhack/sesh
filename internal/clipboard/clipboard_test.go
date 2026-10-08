package clipboard

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// stubSystem makes Find see goos, the environment env, and only the
// programs in tools on PATH.
func stubSystem(t *testing.T, goos string, env map[string]string, tools ...string) {
	t.Helper()
	oldGOOS, oldLookPath, oldGetenv := runtimeGOOS, lookPath, getenv
	t.Cleanup(func() { runtimeGOOS, lookPath, getenv = oldGOOS, oldLookPath, oldGetenv })
	runtimeGOOS = goos
	getenv = func(k string) string { return env[k] }
	lookPath = func(name string) (string, error) {
		if slices.Contains(tools, name) {
			return "/usr/bin/" + name, nil
		}
		return "", exec.ErrNotFound
	}
}

// stubExec records each command sesh runs and runs run(name, args) in its
// place.
func stubExec(t *testing.T, run func(name string, args ...string) *exec.Cmd) *[][]string {
	t.Helper()
	old := execCommand
	t.Cleanup(func() { execCommand = old })
	var calls [][]string
	execCommand = func(name string, args ...string) *exec.Cmd {
		calls = append(calls, append([]string{name}, args...))
		return run(name, args...)
	}
	return &calls
}

// waitForFile waits for path to hold want, as a detached command writes it.
func waitForFile(t *testing.T, path, want string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		got, err := os.ReadFile(path)
		if err == nil && string(got) == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s = %q, %v; want %q", filepath.Base(path), got, err, want)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestFind(t *testing.T) {
	wayland := map[string]string{"WAYLAND_DISPLAY": "wayland-0"}
	x11 := map[string]string{"DISPLAY": ":0"}
	both := map[string]string{"WAYLAND_DISPLAY": "wayland-0", "DISPLAY": ":0"}
	tests := map[string]struct {
		env     map[string]string
		goos    string
		want    string
		wantSub string
		tools   []string
	}{
		"macOS":                          {goos: "darwin", want: "pbcopy"},
		"Wayland":                        {goos: "linux", env: wayland, tools: []string{"wl-copy", "wl-paste", "xclip"}, want: "wl-copy"},
		"Wayland without wl-paste":       {goos: "linux", env: wayland, tools: []string{"wl-copy"}, wantSub: "install wl-clipboard (wl-copy)"},
		"Wayland with XWayland and xsel": {goos: "linux", env: both, tools: []string{"xsel"}, want: "xsel"},
		"Wayland with XWayland, none":    {goos: "linux", env: both, wantSub: "install wl-clipboard (wl-copy), or xclip or xsel"},
		"X11 prefers xclip":              {goos: "linux", env: x11, tools: []string{"xclip", "xsel"}, want: "xclip"},
		"X11 with xsel":                  {goos: "linux", env: x11, tools: []string{"xsel"}, want: "xsel"},
		"X11 ignores wl-copy":            {goos: "linux", env: x11, tools: []string{"wl-copy", "wl-paste"}, wantSub: "install xclip or xsel"},
		"no display, as over SSH":        {goos: "linux", tools: []string{"wl-copy", "wl-paste", "xclip"}, wantSub: "use --show instead"},
		"Windows":                        {goos: "windows", wantSub: "unsupported platform: windows"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			stubSystem(t, tc.goos, tc.env, tc.tools...)
			tool, err := Find()
			if tc.wantSub != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantSub) {
					t.Fatalf("Find() = %v, %v; want an error containing %q", tool.Name, err, tc.wantSub)
				}
				var missing *MissingToolError
				if strings.Contains(tc.wantSub, "install") && !errors.As(err, &missing) {
					t.Errorf("Find() = %T, want a *MissingToolError", err)
				}
				return
			}
			if err != nil || tool.Name != tc.want {
				t.Fatalf("Find() = %q, %v; want %q", tool.Name, err, tc.want)
			}
		})
	}
	t.Run("no display is ErrNoDisplay", func(t *testing.T) {
		stubSystem(t, "linux", nil)
		if _, err := Find(); !errors.Is(err, ErrNoDisplay) {
			t.Errorf("err = %v, want ErrNoDisplay", err)
		}
	})
}

// Copy runs the tool's copy command with the text on its stdin.
func TestCopy(t *testing.T) {
	tests := map[string]struct {
		env      map[string]string
		goos     string
		text     string
		wantArgs string
		tools    []string
	}{
		"macOS":            {goos: "darwin", text: "s3cret", wantArgs: "pbcopy"},
		"empty text":       {goos: "darwin", text: "", wantArgs: "pbcopy"},
		"multiline quotes": {goos: "darwin", text: "line1\n'q' \"dq\" $v", wantArgs: "pbcopy"},
		"Wayland":          {goos: "linux", env: map[string]string{"WAYLAND_DISPLAY": "w"}, tools: []string{"wl-copy", "wl-paste"}, text: "s3cret", wantArgs: "wl-copy"},
		"xclip":            {goos: "linux", env: map[string]string{"DISPLAY": ":0"}, tools: []string{"xclip"}, text: "s3cret", wantArgs: "xclip -selection clipboard"},
		"xsel":             {goos: "linux", env: map[string]string{"DISPLAY": ":0"}, tools: []string{"xsel"}, text: "s3cret", wantArgs: "xsel --clipboard --input"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			stubSystem(t, tc.goos, tc.env, tc.tools...)
			out := filepath.Join(t.TempDir(), "clip")
			calls := stubExec(t, func(string, ...string) *exec.Cmd { return exec.Command("sh", "-c", `cat > "$0"`, out) })
			if err := Copy(tc.text); err != nil {
				t.Fatalf("Copy: %v", err)
			}
			if len(*calls) != 1 || strings.Join((*calls)[0], " ") != tc.wantArgs {
				t.Errorf("ran %v, want [%s]", *calls, tc.wantArgs)
			}
			waitForFile(t, out, tc.text)
		})
	}
}

func TestCopy_Errors(t *testing.T) {
	tests := map[string]struct {
		run     func(string, ...string) *exec.Cmd
		wantSub string
	}{
		"tool fails":        {run: func(string, ...string) *exec.Cmd { return exec.Command("false") }, wantSub: "exit status 1"},
		"tool not runnable": {run: func(string, ...string) *exec.Cmd { return exec.Command("/nonexistent/pbcopy") }, wantSub: "no such file"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			stubSystem(t, "darwin", nil)
			stubExec(t, tc.run)
			if err := Copy("s3cret"); err == nil || !strings.Contains(err.Error(), tc.wantSub) {
				t.Errorf("Copy() = %v, want an error containing %q", err, tc.wantSub)
			}
		})
	}
	t.Run("nothing found runs nothing", func(t *testing.T) {
		stubSystem(t, "linux", nil)
		calls := stubExec(t, func(string, ...string) *exec.Cmd { return exec.Command("true") })
		if err := Copy("s3cret"); !errors.Is(err, ErrNoDisplay) {
			t.Errorf("Copy() = %v, want ErrNoDisplay", err)
		}
		if len(*calls) != 0 {
			t.Errorf("ran %v, want nothing", *calls)
		}
	})
}

// CopyWithAutoClear copies, then starts the clearing script with the
// secret on its stdin.
func TestCopyWithAutoClear(t *testing.T) {
	stubSystem(t, "linux", map[string]string{"DISPLAY": ":0"}, "xclip")
	stdin := filepath.Join(t.TempDir(), "stdin")
	calls := stubExec(t, func(name string, _ ...string) *exec.Cmd {
		if name == "sh" {
			return exec.Command("sh", "-c", `cat > "$0.tmp" && mv "$0.tmp" "$0"`, stdin)
		}
		return exec.Command("true")
	})
	if err := CopyWithAutoClear("s3cret", 30*time.Second); err != nil {
		t.Fatalf("CopyWithAutoClear: %v", err)
	}
	if len(*calls) != 2 || (*calls)[0][0] != "xclip" || (*calls)[1][0] != "sh" {
		t.Fatalf("ran %v, want xclip then sh", *calls)
	}
	waitForFile(t, stdin, "s3cret\n")
}

// The script sleeps a whole number of seconds, at least one, reads the
// whole secret (not one line), and uses the tool's own paste and clear.
func TestSpawnClear_ScriptShape(t *testing.T) {
	tests := map[string]struct {
		env       map[string]string
		goos      string
		tool      string
		wantSleep string
		wantPaste string
		wantClear string
		timeout   time.Duration
	}{
		"macOS":                     {goos: "darwin", timeout: 30 * time.Second, wantSleep: "sleep 30", wantPaste: "current=$(pbpaste ", wantClear: "printf '' | pbcopy"},
		"sub-second rounds up to 1": {goos: "darwin", timeout: 500 * time.Millisecond, wantSleep: "sleep 1", wantPaste: "pbpaste", wantClear: "pbcopy"},
		"zero clamps to 1":          {goos: "darwin", timeout: 0, wantSleep: "sleep 1", wantPaste: "pbpaste", wantClear: "pbcopy"},
		"Wayland":                   {goos: "linux", env: map[string]string{"WAYLAND_DISPLAY": "w"}, tool: "wl-copy", timeout: 45 * time.Second, wantSleep: "sleep 45", wantPaste: "current=$(wl-paste --no-newline ", wantClear: "wl-copy --clear"},
		"xclip":                     {goos: "linux", env: map[string]string{"DISPLAY": ":0"}, tool: "xclip", timeout: 30 * time.Second, wantSleep: "sleep 30", wantPaste: "current=$(xclip -selection clipboard -o ", wantClear: "printf '' | xclip -selection clipboard"},
		"xsel":                      {goos: "linux", env: map[string]string{"DISPLAY": ":0"}, tool: "xsel", timeout: 30 * time.Second, wantSleep: "sleep 30", wantPaste: "current=$(xsel --clipboard --output ", wantClear: "xsel --clipboard --clear"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			stubSystem(t, tc.goos, tc.env, "wl-copy", "wl-paste", tc.tool)
			tool, err := Find()
			if err != nil {
				t.Fatal(err)
			}
			calls := stubExec(t, func(string, ...string) *exec.Cmd { return exec.Command("true") })
			if err := spawnClear(tool, "the-secret", tc.timeout); err != nil {
				t.Fatalf("spawnClear: %v", err)
			}
			script := (*calls)[0][2]
			for _, want := range []string{tc.wantSleep + "\n", "expected=$(cat)", tc.wantPaste, tc.wantClear} {
				if !strings.Contains(script, want) {
					t.Errorf("script should contain %q, got:\n%s", want, script)
				}
			}
			if strings.Contains(script, "read -r") {
				t.Errorf("script should not use `read -r`, which reads only the first line:\n%s", script)
			}
		})
	}
}

// Runs the real clearing script against a stand-in clipboard file: it is
// cleared when it still holds the secret, multiline included, and left
// alone when something else was copied since.
func TestSpawnClear_RunsScript(t *testing.T) {
	secret := "line1\nline2\nwith spaces and 'quotes' $HOME"
	tests := map[string]struct {
		clipboard   string
		wantCleared bool
	}{
		"still the secret":      {clipboard: secret, wantCleared: true},
		"something else copied": {clipboard: "copied since", wantCleared: false},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			clip := filepath.Join(t.TempDir(), "clip")
			if err := os.WriteFile(clip, []byte(tc.clipboard), 0o600); err != nil {
				t.Fatal(err)
			}
			tool := Tool{Name: "stub", paste: "cat '" + clip + "'", clear: "printf '' > '" + clip + "'"}
			// Run the real script, detached as sesh runs it, and mark when
			// it has finished.
			done := clip + ".done"
			stubExec(t, func(name string, args ...string) *exec.Cmd {
				return exec.Command(name, args[0], args[1]+"\necho done > '"+done+"'")
			})
			if err := spawnClear(tool, secret, 0); err != nil {
				t.Fatal(err)
			}
			waitForFile(t, done, "done\n")
			got, err := os.ReadFile(clip)
			if err != nil {
				t.Fatal(err)
			}
			if cleared := len(got) == 0; cleared != tc.wantCleared {
				t.Errorf("clipboard after = %q, want cleared = %v", got, tc.wantCleared)
			}
		})
	}
}
