package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"

	"github.com/bashhack/sesh/internal/password"
	"github.com/bashhack/sesh/internal/secure"
	"github.com/bashhack/sesh/internal/vault"
)

const gitCredentialUsage = `Usage: sesh git-credential get
  A git credential helper: git asks it for a site's password, and it gives
  the one in sesh. Set it up once:

    git config --global credential.helper '!sesh git-credential'

  For https://github.com, it gives the password or API key entry whose URL
  is on github.com (https too), with the username git names, if it names
  one. With no such entry, or several, it gives nothing and git asks as
  usual; with several, it says which. Git also asks it to store a password
  that worked and to erase one that didn't: it does neither, so sesh gives
  only what you added, and a password a site refused once stays.

  Reading the password is recorded in the audit log. When sesh needs the
  master password, it's typed at the terminal, as git's own questions are.`

// maxCredentialInput is the most of git's request read: it's a few lines.
const maxCredentialInput = 64 << 10

// credentialAsk is what git asks a credential helper for.
type credentialAsk struct {
	protocol, host, username string
}

// runGitCredential is sesh git-credential: git's credential helper.
func runGitCredential(app *App, args []string) error {
	if len(args) == 0 || isHelp(args[0]) {
		_, err := fmt.Fprintln(app.Stdout, gitCredentialUsage)
		return err
	}
	if len(args) > 1 {
		return fmt.Errorf("sesh git-credential takes one word, get, store or erase, not %q", strings.Join(args, " "))
	}
	switch args[0] {
	case "store", "erase":
		// Read, so git's write doesn't fail, and let go: sesh holds only
		// what's added to it.
		_, err := io.Copy(io.Discard, io.LimitReader(app.Stdin, maxCredentialInput))
		return err
	case "get":
	default:
		return fmt.Errorf("sesh git-credential takes get, store or erase (git gives it), not %q", args[0])
	}
	ask, err := readCredentialAsk(app.Stdin)
	if err != nil {
		return err
	}
	if ask.protocol == "" || ask.host == "" {
		return nil // nothing sesh can match
	}
	// Whatever goes wrong is said, and git goes on to ask as usual.
	if err := giveCredential(app, ask); err != nil {
		fmt.Fprintf(app.Stderr, "sesh git-credential: %v\n", err) //nolint:errcheck // best-effort message
	}
	return nil
}

// giveCredential writes the username and password of the one entry that
// matches ask, if one does.
func giveCredential(app *App, ask credentialAsk) error {
	store, err := openFilingStore()
	if err != nil {
		return err
	}
	defer closeAuditStore(store)
	entries, err := store.List(&vault.Filter{})
	if err != nil {
		return err
	}
	var matches []vault.Key
	for i := range entries {
		if credentialMatches(&entries[i], ask) {
			matches = append(matches, entries[i].Key)
		}
	}
	switch len(matches) {
	case 0:
		return nil
	case 1:
	default:
		names := make([]string, len(matches))
		for i, k := range matches {
			names[i] = password.EntryName(k)
		}
		return fmt.Errorf("%d entries are for %s://%s (%s): name the username for git (git config credential.%s://%s.username NAME), or give each a different URL",
			len(matches), ask.protocol, ask.host, strings.Join(names, ", "), ask.protocol, ask.host)
	}
	k := matches[0]
	// The master password, if it's asked for, is typed at the terminal:
	// stdin is git's.
	if tty, err := os.Open("/dev/tty"); err == nil {
		defer tty.Close() //nolint:errcheck // read only
		was := terminalIn
		terminalIn = tty
		defer func() { terminalIn = was }()
	}
	secret, err := store.Get(k)
	if err != nil {
		return err
	}
	defer secure.SecureZeroBytes(secret)
	if bytes.ContainsAny(secret, "\n\x00") || strings.ContainsAny(k.Username, "\n\x00") {
		return fmt.Errorf("%s has a line break in it, which git can't take", password.EntryName(k))
	}
	user := ""
	if ask.username == "" && k.Username != "" {
		user = "username=" + k.Username + "\n"
	}
	// Sized first, so it never grows and leaves a copy of the secret.
	var b bytes.Buffer
	b.Grow(len(user) + len("password=") + len(secret) + 1)
	b.WriteString(user)
	b.WriteString("password=")
	b.Write(secret)
	b.WriteByte('\n')
	defer secure.SecureZeroBytes(b.Bytes())
	_, err = app.Stdout.Write(b.Bytes())
	return err
}

// readCredentialAsk reads git's request: key=value lines, up to a blank
// line or the end. A url= line stands for its parts.
func readCredentialAsk(r io.Reader) (credentialAsk, error) {
	var ask credentialAsk
	sc := bufio.NewScanner(io.LimitReader(r, maxCredentialInput))
	sc.Buffer(make([]byte, 0, 4096), maxCredentialInput)
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			break
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch key {
		case "protocol":
			ask.protocol = value
		case "host":
			ask.host = value
		case "username":
			ask.username = value
		case "url":
			if u, err := url.Parse(value); err == nil {
				ask.protocol, ask.host = u.Scheme, u.Host
				if u.User != nil {
					ask.username = u.User.Username()
				}
			}
		}
	}
	if err := sc.Err(); err != nil {
		return credentialAsk{}, fmt.Errorf("read git's request: %w", err)
	}
	return ask, nil
}

// credentialMatches says whether e holds the password git asks for: a
// password or API key whose URL has the protocol and host asked (a port
// that's the protocol's own left out of both), with the username asked,
// if one is.
func credentialMatches(e *vault.Entry, ask credentialAsk) bool {
	if e.Kind != vault.KindPassword && e.Kind != vault.KindAPIKey || e.URL == "" {
		return false
	}
	raw := e.URL
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || !strings.EqualFold(u.Scheme, ask.protocol) {
		return false
	}
	if !strings.EqualFold(hostWithoutDefaultPort(u.Host, u.Scheme), hostWithoutDefaultPort(ask.host, ask.protocol)) {
		return false
	}
	return ask.username == "" || e.Username == ask.username
}

// hostWithoutDefaultPort is host without :443 for https, or :80 for http.
func hostWithoutDefaultPort(host, scheme string) string {
	switch strings.ToLower(scheme) {
	case "https":
		return strings.TrimSuffix(host, ":443")
	case "http":
		return strings.TrimSuffix(host, ":80")
	}
	return host
}
