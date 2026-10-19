package main

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/bashhack/sesh/internal/agent"
	"github.com/bashhack/sesh/internal/database"
	"github.com/bashhack/sesh/internal/sitematch"
	"github.com/bashhack/sesh/internal/touchid"
	"github.com/bashhack/sesh/internal/vault"
)

// sesh browser-host is the program sesh's browser extension talks to: the
// browser starts it for each request, with the calling extension named
// in its arguments (Chrome: its origin; Firefox: the host's manifest and
// the add-on's ID), and swaps one message each way over stdin and stdout.
// It never asks at a terminal: the browser started it, so there's no one
// to type at.

// A message is a 4-byte length, in the machine's byte order (little-endian
// on the Macs and PCs sesh runs on), then that many bytes of UTF-8 JSON.
const (
	// maxBrowserRequest is the longest request read: none needs more.
	maxBrowserRequest = 16 << 10
	// maxBrowserReply is the longest reply the browser takes.
	maxBrowserReply = 1 << 20
)

// browserRequest is a request from the extension. URL is the tab's, which
// the extension's background worker reads from the browser, never from
// the page.
type browserRequest struct {
	Type string `json:"type"`
	URL  string `json:"url,omitempty"`
}

// browserReply is a reply: Status is "ok", or "error" with Code and
// Message, in sesh's usual words, which the popup shows as they are.
type browserReply struct {
	Locked  *bool           `json:"locked,omitempty"`
	TouchID *bool           `json:"touch_id,omitempty"`
	Entries *[]browserEntry `json:"entries,omitempty"` // a match's, [] for none
	Status  string          `json:"status"`
	Code    string          `json:"code,omitempty"`
	Message string          `json:"message,omitempty"`
}

// browserEntry is a login offered for a site: no secret, only what names
// it, and whether a code comes with it.
type browserEntry struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Username string `json:"username,omitempty"`
	TOTP     bool   `json:"totp,omitempty"`
}

// browserError is a request refused, with the code the extension acts on.
type browserError struct{ code, message string }

func (e *browserError) Error() string { return e.message }

// runBrowserHost is sesh browser-host: it reads one request, writes one
// reply, and ends. What's wrong with a request is said in the reply; only
// a broken message stream is an error, which the browser reports.
func runBrowserHost(app *App, _ []string) error {
	if app.StdinIsTerminal != nil && app.StdinIsTerminal() {
		return errors.New("sesh browser-host is started by the browser, for sesh's extension: it isn't run at a terminal")
	}
	body, err := readBrowserMessage(app.Stdin)
	if err != nil {
		return err
	}
	var req browserRequest
	reply := browserReply{Status: "ok"}
	if err := json.Unmarshal(body, &req); err != nil {
		reply = refused(&browserError{"bad_request", "the request isn't JSON sesh reads"})
	} else if err := answerBrowser(&req, &reply); err != nil {
		reply = refused(err)
	}
	return writeBrowserMessage(app.Stdout, &reply)
}

// refused is the reply saying why err stopped a request.
func refused(err error) browserReply {
	if be, ok := errors.AsType[*browserError](err); ok {
		return browserReply{Status: "error", Code: be.code, Message: be.message}
	}
	return browserReply{Status: "error", Code: "failed", Message: err.Error()}
}

// answerBrowser fills reply in for req.
func answerBrowser(req *browserRequest, reply *browserReply) error {
	switch req.Type {
	case "status":
		locked, touchID, err := browserStatus()
		if err != nil {
			return err
		}
		reply.Locked, reply.TouchID = &locked, &touchID
	case "match":
		entries, err := browserMatch(req.URL)
		if err != nil {
			return err
		}
		if entries == nil {
			entries = []browserEntry{}
		}
		reply.Entries = &entries
	default:
		return &browserError{"unknown_request", fmt.Sprintf("sesh doesn't know the request %q: the extension may be newer than sesh", req.Type)}
	}
	return nil
}

// readBrowserMessage reads one message: refused when it's longer than any
// request, empty, or ends early.
func readBrowserMessage(r io.Reader) ([]byte, error) {
	var size uint32
	if err := binary.Read(r, binary.NativeEndian, &size); err != nil {
		return nil, fmt.Errorf("read the request's length: %w", err)
	}
	switch {
	case size == 0:
		return nil, errors.New("the request is empty")
	case size > maxBrowserRequest:
		return nil, fmt.Errorf("the request is %d bytes, more than any sesh reads (%d)", size, maxBrowserRequest)
	}
	body := make([]byte, size)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, fmt.Errorf("read the request: %w", err)
	}
	return body, nil
}

// writeBrowserMessage writes v as one message, refusing one longer than
// the browser takes.
func writeBrowserMessage(w io.Writer, v any) error {
	body, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if len(body) > maxBrowserReply {
		return fmt.Errorf("the reply is %d bytes, more than the browser takes (%d)", len(body), maxBrowserReply)
	}
	msg := binary.NativeEndian.AppendUint32(make([]byte, 0, 4+len(body)), uint32(len(body))) //nolint:gosec // at most maxBrowserReply
	_, err = w.Write(append(msg, body...))
	return err
}

// browserStatus says whether the vault is locked (the agent holds no key
// for it, or isn't running), and whether Touch ID can unlock it here.
func browserStatus() (locked, touchID bool, err error) {
	cfg, err := settings()
	if err != nil {
		return false, false, err
	}
	mat, err := database.ReadUnlockMaterial(cfg.DBPath.Value)
	if errors.Is(err, database.ErrNoVault) {
		return false, false, noVault(cfg.DBPath.Value)
	}
	if err != nil {
		return false, false, err
	}
	locked = true
	if conn, err := agent.DialExisting(); err == nil {
		defer closeAgentConn(conn)
		if st, err := agent.Status(conn); err == nil && agentUnlocks(&st, true, database.UnlockID(mat.Verify)) {
			locked = false
		}
	}
	return locked, touchIDPlatform && touchIDUsable(cfg.DBPath.Value, mat.Verify) && !overSSH(), nil
}

// touchIDUsable says whether Touch ID can unlock the vault at dbPath,
// whose key record verify is: it's on for this vault, and the fingerprints
// haven't changed since, which leaves its Secure Enclave key unusable.
func touchIDUsable(dbPath string, verify []byte) bool {
	f, err := touchid.ReadFile(filepath.Dir(dbPath))
	return err == nil && f.UnlockID == agent.UnlockID(verify) && !fingerprintsChanged(f)
}

// noVault says there's no vault where sesh looks: named, since the
// browser starts sesh without the variables a shell may set (SESH_DB_PATH).
func noVault(dbPath string) error {
	return &browserError{"no_vault", "there's no sesh vault at " + dbPath + " (where sesh looks when the browser starts it): sesh add makes one with your first entry"}
}

// browserMatch is the logins for the site at page, a tab's URL: password
// and API key entries with a URL of that site (its own, or an extra one
// in a url-2, url-3 … field), each saying whether a TOTP entry with its
// name and username gives a code. Names and URLs aren't encrypted, so
// the vault isn't unlocked for this, and nothing secret is read.
func browserMatch(page string) ([]browserEntry, error) {
	scheme, host, ok := sitematch.Of(page)
	if !ok {
		return nil, &browserError{"not_a_site", "sesh fills logins on http and https pages only"}
	}
	cfg, err := settings()
	if err != nil {
		return nil, err
	}
	if vaultMissing(cfg.DBPath.Value) {
		return nil, noVault(cfg.DBPath.Value)
	}
	store, err := database.Open(cfg.DBPath.Value, nil)
	if err != nil {
		return nil, err
	}
	defer store.Close() //nolint:errcheck // a read
	all, err := store.List(&vault.Filter{})
	if err != nil {
		return nil, err
	}
	codes := map[vault.Key]bool{}
	for i := range all {
		if all[i].Kind == vault.KindTOTP {
			codes[all[i].Key] = true
		}
	}
	var found []browserEntry
	for i := range all {
		e := &all[i]
		if e.Kind != vault.KindPassword && e.Kind != vault.KindAPIKey {
			continue
		}
		if !slices.ContainsFunc(entryURLs(e), func(u string) bool { return sitematch.Matches(u, scheme, host) }) {
			continue
		}
		code := vault.Key{Kind: vault.KindTOTP, Service: e.Service, Username: e.Username}
		found = append(found, browserEntry{ID: e.Key.String(), Name: e.Service, Username: e.Username, TOTP: codes[code]})
	}
	slices.SortFunc(found, func(a, b browserEntry) int {
		if c := strings.Compare(strings.ToLower(a.Name), strings.ToLower(b.Name)); c != 0 {
			return c
		}
		return strings.Compare(a.Username, b.Username)
	})
	return found, nil
}

// extraURL is the name of a field with another of an entry's URLs.
var extraURL = regexp.MustCompile(`(?i)^url-([2-9]|[1-9]\d+)$`)

// entryURLs is e's URLs: its own, and those in plain url-2, url-3 …
// fields.
func entryURLs(e *vault.Entry) []string {
	urls := []string{e.URL}
	for _, f := range e.Fields {
		if !f.Secret && extraURL.MatchString(f.Name) {
			urls = append(urls, strings.TrimSpace(string(f.Value)))
		}
	}
	return urls
}
