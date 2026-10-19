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
// (a script printing what it's given) for the browser's script to run.
func browserSetup(t *testing.T) (homes []browserHome, script, sesh string) {
	t.Helper()
	home := t.TempDir()
	goos := runtime.GOOS
	if goos != "darwin" && goos != "linux" {
		t.Skip("browsers are set up on macOS and Linux")
	}
	homes = browserHomes(goos, home)
	for _, b := range homes {
		if err := os.MkdirAll(b.root, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	dir := t.TempDir()
	sesh = filepath.Join(dir, "my sesh")                                                  // a space, which the script must quote
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
	for _, dir := range []string{homes[1].root, homes[1].hosts} {
		if err := os.RemoveAll(dir); err != nil {
			t.Fatal(err)
		}
	}
	app = agentTestApp()
	if err := browserInstall(app, homes, script); err != nil || strings.Contains(app.Stdout.(*bytes.Buffer).String(), homes[1].name) {
		t.Errorf("one browser: %v\n%s", err, app.Stdout)
	}
	if err := os.RemoveAll(homes[0].root); err != nil {
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
	row := func() string {
		t.Helper()
		var c doctorChecks
		checkBrowser(&c)
		return c.rows.String()
	}
	if got := row(); !strings.Contains(got, "-     Browser         the extension isn't set up") {
		t.Errorf("not set up: %q", got)
	}
	_, _, sesh := browserSetup(t)
	homes := browserHomes(runtime.GOOS, home)
	for _, b := range homes {
		if err := os.MkdirAll(b.root, 0o700); err != nil {
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
	theirs := filepath.Join(homes[0].hosts, browserHostName+".json")
	if err := os.WriteFile(theirs, []byte(`{"path":"/opt/other/host"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := row(); !strings.Contains(got, "Chrome starts /opt/other/host") {
		t.Errorf("another program: %q", got)
	}
}

// The browsers' folders, as their docs give them, on each system.
func TestBrowser_Homes(t *testing.T) {
	for goos, want := range map[string][]string{
		"darwin": {"/h/Library/Application Support/Google/Chrome/NativeMessagingHosts", "/h/Library/Application Support/Mozilla/NativeMessagingHosts"},
		"linux":  {"/h/.config/google-chrome/NativeMessagingHosts", "/h/.mozilla/native-messaging-hosts"},
	} {
		var got []string
		for _, b := range browserHomes(goos, "/h") {
			got = append(got, b.hosts)
		}
		if strings.Join(got, ", ") != strings.Join(want, ", ") {
			t.Errorf("%s: %q, want %q", goos, got, want)
		}
	}
	if browserHomes("windows", "/h") != nil {
		t.Error("windows has browsers set up")
	}
}
