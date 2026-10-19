package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/bashhack/sesh/internal/database"
)

// browserSetup is a home with Chrome's and Firefox's folders, and a sesh
// (a script printing what it's given, at a path with a space, which the
// script must quote) for the browser's script to run.
func browserSetup(t *testing.T) (homes []browserHome, script, sesh string) {
	return browserSetupAt(t, "my sesh")
}

// browserSetupAt is browserSetup, its sesh named name.
func browserSetupAt(t *testing.T, name string) (homes []browserHome, script, sesh string) {
	t.Helper()
	home := t.TempDir()
	goos := runtime.GOOS
	if goos != "darwin" && goos != "linux" {
		t.Skip("browsers are set up on macOS and Linux")
	}
	homes = browserHomes(goos, home, "")
	for _, b := range homes {
		if err := os.MkdirAll(b.roots[0], 0o700); err != nil {
			t.Fatal(err)
		}
	}
	dir := t.TempDir()
	sesh = filepath.Join(dir, name)
	if err := os.WriteFile(sesh, []byte("#!/bin/sh\necho \"$@\"\n"), 0o700); err != nil { //nolint:gosec // a test program
		t.Fatal(err)
	}
	was := seshForBrowser
	t.Cleanup(func() { seshForBrowser = was })
	seshForBrowser = func() (string, error) { return sesh, nil }
	return homes, filepath.Join(dir, "data", "browser-host"), sesh
}

// install writes, for each browser there, the file naming sesh's script
// with only the extension let start it, and the script, which runs sesh
// browser-host with what the browser gives it.
func TestBrowser_Install(t *testing.T) {
	homes, script, _ := browserSetup(t)
	app := agentTestApp()
	if err := browserInstall(app, homes, script); err != nil {
		t.Fatal(err)
	}
	for _, b := range homes {
		data, err := os.ReadFile(filepath.Join(b.hosts, browserHostName+".json")) //nolint:gosec // the test's own file
		if err != nil {
			t.Fatalf("%s: %v", b.name, err)
		}
		var m hostManifest
		if err := json.Unmarshal(data, &m); err != nil {
			t.Fatal(err)
		}
		want := hostManifest{Name: "io.github.bashhack.sesh", Description: m.Description, Path: script, Type: "stdio"}
		if b.firefox {
			want.AllowedExtensions = []string{"sesh@bashhack.github.io"}
		} else {
			want.AllowedOrigins = []string{"chrome-extension://dgamnkgjechpcflbfflndpegmcbpdajj/"}
		}
		if got := must(json.Marshal(m)); string(got) != string(must(json.Marshal(want))) {
			t.Errorf("%s's file: %s, want %s", b.name, got, must(json.Marshal(want)))
		}
	}
	out, err := exec.Command(script, "chrome-extension://dgamnkgjechpcflbfflndpegmcbpdajj/").Output() //nolint:gosec // the test's own script
	if err != nil || strings.TrimSpace(string(out)) != "browser-host chrome-extension://dgamnkgjechpcflbfflndpegmcbpdajj/" {
		t.Errorf("the script ran sesh with %q, %v", out, err)
	}
	// Only browsers there are set up; with none, it says so.
	for _, dir := range append(homes[1].roots, homes[1].hosts) {
		if err := os.RemoveAll(dir); err != nil {
			t.Fatal(err)
		}
	}
	app = agentTestApp()
	if err := browserInstall(app, homes, script); err != nil || strings.Contains(app.Stdout.(*bytes.Buffer).String(), homes[1].name) {
		t.Errorf("one browser: %v\n%s", err, app.Stdout)
	}
	if err := os.RemoveAll(homes[0].roots[0]); err != nil {
		t.Fatal(err)
	}
	if err := browserInstall(agentTestApp(), homes, script); err == nil || !strings.Contains(err.Error(), "found neither Chrome nor Firefox") {
		t.Errorf("no browsers: %v", err)
	}
}

// uninstall removes sesh's files, leaving another program's, then says
// there's nothing left to remove.
func TestBrowser_Uninstall(t *testing.T) {
	homes, script, _ := browserSetup(t)
	if err := browserInstall(agentTestApp(), homes, script); err != nil {
		t.Fatal(err)
	}
	theirs := filepath.Join(homes[1].hosts, browserHostName+".json")
	if err := os.WriteFile(theirs, []byte(`{"name":"io.github.bashhack.sesh","path":"/opt/other/host"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	app := agentTestApp()
	if err := browserUninstall(app, homes, script); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(homes[0].hosts, browserHostName+".json")); !os.IsNotExist(err) {
		t.Errorf("sesh's file is still there: %v", err)
	}
	if _, err := os.Stat(script); !os.IsNotExist(err) {
		t.Errorf("the script is still there: %v", err)
	}
	if _, err := os.Stat(theirs); err != nil || !strings.Contains(app.Stderr.(*bytes.Buffer).String(), "not sesh's script") {
		t.Errorf("another program's file: %v\n%s", err, app.Stderr)
	}
	// One that can't be read is left, and said so.
	if err := os.WriteFile(theirs, []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	app = agentTestApp()
	if err := browserUninstall(app, homes, script); err != nil || !strings.Contains(app.Stderr.(*bytes.Buffer).String(), "it can't be read") {
		t.Errorf("an unreadable file: %v\n%s", err, app.Stderr)
	}
	app = agentTestApp()
	if err := os.Remove(theirs); err != nil {
		t.Fatal(err)
	}
	if err := browserUninstall(app, homes, script); err != nil || !strings.Contains(app.Stdout.(*bytes.Buffer).String(), "Nothing to remove") {
		t.Errorf("again: %v\n%s", err, app.Stdout)
	}
}

func must(b []byte, err error) []byte {
	if err != nil {
		panic(err)
	}
	return b
}

// sesh doctor's row: not set up; set up for each browser; then the script's
// sesh gone, or a browser starting another program.
func TestBrowser_Doctor(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_DATA_HOME", "")
	t.Setenv("XDG_CONFIG_HOME", "")
	row := func() string {
		t.Helper()
		var c doctorChecks
		checkBrowser(&c)
		return c.rows.String()
	}
	if got := row(); !strings.Contains(got, "-     Browser         the extension isn't set up") {
		t.Errorf("not set up: %q", got)
	}
	// A sesh whose path needs no quoting, as Homebrew's /opt/homebrew/bin/sesh.
	_, _, sesh := browserSetupAt(t, "sesh")
	homes := homesHere(home)
	for _, b := range homes {
		if err := os.MkdirAll(b.roots[0], 0o700); err != nil {
			t.Fatal(err)
		}
	}
	dataDir, err := database.DefaultDataDir()
	if err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(dataDir, "browser-host")
	if err := browserInstall(agentTestApp(), homes, script); err != nil {
		t.Fatal(err)
	}
	if got := row(); !strings.Contains(got, "ok    Browser         the extension is set up for Chrome and Firefox") {
		t.Errorf("set up: %q", got)
	}
	if err := os.Remove(sesh); err != nil {
		t.Fatal(err)
	}
	if got := row(); !strings.Contains(got, "warn  Browser") || !strings.Contains(got, "which isn't there") {
		t.Errorf("sesh gone: %q", got)
	}
	if err := os.Remove(script); err != nil {
		t.Fatal(err)
	}
	if got := row(); !strings.Contains(got, "is missing or can't be run") {
		t.Errorf("the script gone: %q", got)
	}
	if err := os.WriteFile(filepath.Join(homes[1].hosts, browserHostName+".json"), []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := row(); !strings.Contains(got, "Firefox's file can't be read") {
		t.Errorf("an unreadable file: %q", got)
	}
	theirs := filepath.Join(homes[0].hosts, browserHostName+".json")
	if err := os.WriteFile(theirs, []byte(`{"path":"/opt/other/host"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := row(); !strings.Contains(got, "Chrome starts /opt/other/host") {
		t.Errorf("another program: %q", got)
	}
}

// The browsers' folders, as their docs give them, on each system: where
// hosts' files go, and where each browser is known to be there by
// (Firefox by its profiles, as it no longer makes its old folders).
func TestBrowser_Homes(t *testing.T) {
	for _, tc := range []struct {
		goos, xdg string
		want      []string
	}{
		{"darwin", "", []string{
			"/h/Library/Application Support/Google/Chrome/NativeMessagingHosts if /h/Library/Application Support/Google/Chrome",
			"/h/Library/Application Support/Mozilla/NativeMessagingHosts if /h/Library/Application Support/Firefox, /h/Library/Application Support/Mozilla",
		}},
		{"linux", "", []string{
			"/h/.config/google-chrome/NativeMessagingHosts if /h/.config/google-chrome",
			"/h/.mozilla/native-messaging-hosts if /h/.mozilla, /h/.config/mozilla, /h/snap/firefox/common/.mozilla",
		}},
		{"linux", "/x", []string{
			"/h/.config/google-chrome/NativeMessagingHosts if /h/.config/google-chrome",
			"/h/.mozilla/native-messaging-hosts if /h/.mozilla, /x/mozilla, /h/snap/firefox/common/.mozilla",
		}},
		{"linux", "relative", []string{
			"/h/.config/google-chrome/NativeMessagingHosts if /h/.config/google-chrome",
			"/h/.mozilla/native-messaging-hosts if /h/.mozilla, /h/.config/mozilla, /h/snap/firefox/common/.mozilla",
		}},
	} {
		var got []string
		for _, b := range browserHomes(tc.goos, "/h", tc.xdg) {
			got = append(got, b.hosts+" if "+strings.Join(b.roots, ", "))
		}
		if strings.Join(got, "; ") != strings.Join(tc.want, "; ") {
			t.Errorf("%s %q: %q, want %q", tc.goos, tc.xdg, got, tc.want)
		}
	}
	if browserHomes("windows", "/h", "") != nil {
		t.Error("windows has browsers set up")
	}
}

// Firefox is found by its profiles' folder alone: a fresh Firefox makes no
// other; the hosts folder is made.
func TestBrowser_InstallFindsAFreshFirefox(t *testing.T) {
	homes, script, _ := browserSetup(t)
	for _, b := range homes {
		for _, r := range b.roots {
			if err := os.RemoveAll(r); err != nil {
				t.Fatal(err)
			}
		}
	}
	firefox := homes[1]
	profiles := firefox.roots[0]
	if runtime.GOOS == "linux" {
		profiles = firefox.roots[1] // ~/.config/mozilla, Firefox 147's
	}
	if err := os.MkdirAll(profiles, 0o700); err != nil {
		t.Fatal(err)
	}
	app := agentTestApp()
	if err := browserInstall(app, homes, script); err != nil {
		t.Fatalf("a fresh Firefox: %v", err)
	}
	if _, err := os.Stat(filepath.Join(firefox.hosts, browserHostName+".json")); err != nil {
		t.Errorf("Firefox's file: %v\n%s", err, app.Stdout)
	}
}

// Only go run's (and go test's) temporary builds are refused, not a sesh
// installed in a folder whose name starts with go-build.
func TestBrowser_GoRunBuild(t *testing.T) {
	for path, want := range map[string]bool{
		"/var/folders/xy/T/go-build1234567/b001/exe/sesh": true,
		"/tmp/go-build99/b001/exe/sesh":                   true,
		"/opt/homebrew/bin/sesh":                          false,
		"/Users/a/go-builds/bin/sesh":                     false,
		"/opt/go-build-tools/sesh":                        false,
		"/home/a/go/bin/sesh":                             false,
	} {
		if got := goRunBuild(path); got != want {
			t.Errorf("goRunBuild(%q) = %v, want %v", path, got, want)
		}
	}
}
