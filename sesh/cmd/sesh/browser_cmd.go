package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"github.com/bashhack/sesh/internal/atomicfile"
	"github.com/bashhack/sesh/internal/database"
	"github.com/bashhack/sesh/internal/shell"
)

const browserUsage = `Usage:
  sesh browser install     Set up sesh's browser extension: tell Chrome and Firefox where sesh is
  sesh browser uninstall   Undo it

The extension (github.com/bashhack/sesh-browser) asks sesh for a site's
login through the browser's native messaging. install writes, for each of
Chrome and Firefox you have, the file that says which program the browser
starts for it, and that program: a small script that runs
sesh browser-host. Run it again after moving sesh; a Homebrew upgrade
needs nothing, as the script names Homebrew's link to sesh.`

// browserHostName is the name the extension asks the browser for sesh by.
const browserHostName = "io.github.bashhack.sesh"

// The extension's IDs: Chrome's fixed by the public key in its manifest,
// Firefox's by its add-on ID. Only they may start sesh's host.
const (
	chromeExtensionID  = "dgamnkgjechpcflbfflndpegmcbpdajj"
	firefoxExtensionID = "sesh@bashhack.github.io"
)

// browserHome is a browser whose native messaging hosts sesh sets up: its
// folder (from home), there when the browser has been run, and the folder
// for hosts inside it; firefox says which kind of file it takes.
type browserHome struct {
	name, root, hosts string
	firefox           bool
}

// browserHomes are the browsers sesh sets up on goos, as their docs give
// the folders (Chrome: developer.chrome.com, native messaging; Firefox:
// MDN, native manifests).
func browserHomes(goos, home string) []browserHome {
	switch goos {
	case "darwin":
		as := filepath.Join(home, "Library", "Application Support")
		return []browserHome{
			{name: "Chrome", root: filepath.Join(as, "Google", "Chrome"), hosts: filepath.Join(as, "Google", "Chrome", "NativeMessagingHosts")},
			{name: "Firefox", root: filepath.Join(as, "Mozilla"), hosts: filepath.Join(as, "Mozilla", "NativeMessagingHosts"), firefox: true},
		}
	case "linux":
		return []browserHome{
			{name: "Chrome", root: filepath.Join(home, ".config", "google-chrome"), hosts: filepath.Join(home, ".config", "google-chrome", "NativeMessagingHosts")},
			{name: "Firefox", root: filepath.Join(home, ".mozilla"), hosts: filepath.Join(home, ".mozilla", "native-messaging-hosts"), firefox: true},
		}
	}
	return nil
}

// hostManifest is the file that tells a browser about sesh's host.
type hostManifest struct {
	Name              string   `json:"name"`
	Description       string   `json:"description"`
	Path              string   `json:"path"`
	Type              string   `json:"type"`
	AllowedOrigins    []string `json:"allowed_origins,omitempty"`    // Chrome's
	AllowedExtensions []string `json:"allowed_extensions,omitempty"` // Firefox's
}

// manifestFor is the host file for b, starting the script at script.
func manifestFor(b *browserHome, script string) hostManifest {
	m := hostManifest{Name: browserHostName, Description: "sesh, for its browser extension", Path: script, Type: "stdio"}
	if b.firefox {
		m.AllowedExtensions = []string{firefoxExtensionID}
	} else {
		m.AllowedOrigins = []string{"chrome-extension://" + chromeExtensionID + "/"}
	}
	return m
}

// runBrowser is sesh browser: install or uninstall.
func runBrowser(app *App, args []string) error {
	if len(args) == 0 || isHelp(args[0]) {
		_, err := fmt.Fprintln(app.Stdout, browserUsage)
		return err
	}
	if len(args) > 1 {
		return fmt.Errorf("sesh browser %s takes nothing more, got %q", args[0], strings.Join(args[1:], " "))
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	dataDir, err := database.DefaultDataDir()
	if err != nil {
		return err
	}
	script := filepath.Join(dataDir, "browser-host")
	switch args[0] {
	case "install":
		return browserInstall(app, browserHomes(runtime.GOOS, home), script)
	case "uninstall":
		return browserUninstall(app, browserHomes(runtime.GOOS, home), script)
	}
	return fmt.Errorf("sesh browser takes install or uninstall, not %q", args[0])
}

// browserInstall writes the script, and the host file for each browser
// there is (one that's been run: its folder is there).
func browserInstall(app *App, homes []browserHome, script string) error {
	var found []browserHome
	for _, b := range homes {
		if fi, err := os.Stat(b.root); err == nil && fi.IsDir() {
			found = append(found, b)
		}
	}
	if len(found) == 0 {
		return errors.New("sesh found neither Chrome nor Firefox here: run the browser once, then sesh browser install again")
	}
	sesh, err := seshForBrowser()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(script), 0o700); err != nil {
		return err
	}
	body := "#!/bin/sh\n# Written by sesh browser install: the browser starts this for sesh's extension.\nexec " + shell.Quote(sesh) + " browser-host \"$@\"\n"
	if err := atomicfile.Write(script, []byte(body), 0o700); err != nil { //nolint:gosec // the script must be run
		return fmt.Errorf("write %s: %w", script, err)
	}
	for _, b := range found {
		data, err := json.MarshalIndent(manifestFor(&b, script), "", "  ")
		if err != nil {
			return err
		}
		if err := os.MkdirAll(b.hosts, 0o755); err != nil { //nolint:gosec // the browser's own folder
			return err
		}
		file := filepath.Join(b.hosts, browserHostName+".json")
		if err := atomicfile.Write(file, append(data, '\n'), 0o644); err != nil { //nolint:gosec // the browser reads it; it holds no secret
			return fmt.Errorf("write %s: %w", file, err)
		}
		fmt.Fprintf(app.Stdout, "✅ %s: %s\n", b.name, file) //nolint:errcheck // a status line
	}
	_, err = fmt.Fprintf(app.Stdout, "The browser starts %s, which runs %s browser-host. Load the extension, then open a site you have a login for.\n", script, sesh)
	return err
}

// browserUninstall removes the host files sesh wrote (ones naming another
// program are left) and the script.
func browserUninstall(app *App, homes []browserHome, script string) error {
	removed := 0
	for _, b := range homes {
		file := filepath.Join(b.hosts, browserHostName+".json")
		data, err := os.ReadFile(file) //nolint:gosec // the browser's folder
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		var m hostManifest
		if json.Unmarshal(data, &m) != nil || m.Path != script {
			fmt.Fprintf(app.Stderr, "Left %s: it starts %s, not sesh's script\n", file, m.Path) //nolint:errcheck // a status line
			continue
		}
		if err := os.Remove(file); err != nil {
			return err
		}
		removed++
		fmt.Fprintf(app.Stdout, "Removed %s's: %s\n", b.name, file) //nolint:errcheck // a status line
	}
	switch err := os.Remove(script); {
	case err == nil:
		removed++
	case !errors.Is(err, os.ErrNotExist):
		return err
	}
	if removed == 0 {
		_, err := fmt.Fprintln(app.Stdout, "Nothing to remove: sesh's browser extension wasn't set up here.")
		return err
	}
	return nil
}

// seshForBrowser is the sesh the browser's script runs; tests replace it.
var seshForBrowser = stableSeshPath

// stableSeshPath is the path the browser's script runs sesh by: the sesh
// on PATH when it's this program (Homebrew's link, which an upgrade keeps
// pointing at the new sesh), else this program's own path.
func stableSeshPath() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	resolved, err := filepath.EvalSymlinks(exe)
	if err != nil {
		return "", err
	}
	if onPath, err := lookPath("sesh"); err == nil {
		if abs, err := filepath.Abs(onPath); err == nil {
			if r, err := filepath.EvalSymlinks(abs); err == nil && r == resolved {
				return abs, nil
			}
		}
	}
	return exe, nil
}

// scriptSesh is the sesh a browser-host script runs: its exec line's path.
var scriptSesh = regexp.MustCompile(`(?m)^exec '((?:[^']|'\\'')*)' browser-host`)

// checkBrowser says which browsers sesh's extension is set up for, and
// whether what they'd start is there: sesh doctor's row.
func checkBrowser(c *doctorChecks) {
	home, err := os.UserHomeDir()
	if err != nil {
		return
	}
	dataDir, err := database.DefaultDataDir()
	if err != nil {
		return
	}
	script := filepath.Join(dataDir, "browser-host")
	var set, wrong []string
	for _, b := range browserHomes(runtime.GOOS, home) {
		data, err := os.ReadFile(filepath.Join(b.hosts, browserHostName+".json")) //nolint:gosec // the browser's folder
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		var m hostManifest
		switch {
		case err != nil || json.Unmarshal(data, &m) != nil:
			wrong = append(wrong, b.name+"'s file can't be read")
		case m.Path != script:
			wrong = append(wrong, b.name+" starts "+tildePath(m.Path))
		default:
			set = append(set, b.name)
		}
	}
	if len(set) == 0 && len(wrong) == 0 {
		c.row(markNone, "Browser", "the extension isn't set up (sesh browser install)")
		return
	}
	data, err := os.ReadFile(script) //nolint:gosec // sesh's own file
	switch fi, serr := os.Stat(script); {
	case err != nil || serr != nil || fi.Mode()&0o100 == 0:
		wrong = append(wrong, "the script the browser starts, "+tildePath(script)+", is missing or can't be run")
	default:
		if m := scriptSesh.FindSubmatch(data); m == nil {
			wrong = append(wrong, tildePath(script)+" doesn't say which sesh it runs")
		} else if target := strings.ReplaceAll(string(m[1]), `'\''`, "'"); !isFile(target) {
			wrong = append(wrong, tildePath(script)+" runs "+tildePath(target)+", which isn't there")
		}
	}
	if len(wrong) > 0 {
		c.row(markWarn, "Browser", strings.Join(wrong, "; "))
		c.todo("Set the browser extension up again:", "sesh browser install")
		return
	}
	c.row(markOK, "Browser", "the extension is set up for "+strings.Join(set, " and "))
}

// isFile says whether path is a file there.
func isFile(path string) bool {
	fi, err := os.Stat(path) //nolint:gosec // a path sesh's own script names, only looked at
	return err == nil && !fi.IsDir()
}
