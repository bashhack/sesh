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
	"time"

	"github.com/bashhack/sesh/internal/agent"
	"github.com/bashhack/sesh/internal/database"
	"github.com/bashhack/sesh/internal/secure"
	"github.com/bashhack/sesh/internal/sitematch"
	"github.com/bashhack/sesh/internal/totp"
	"github.com/bashhack/sesh/internal/touchid"
	"github.com/bashhack/sesh/internal/tui"
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
// the extension reads from the browser (tabs.query), never from the page.
type browserRequest struct {
	Type string `json:"type"`
	URL  string `json:"url,omitempty"`
	ID   string `json:"id,omitempty"` // fill's entry
	// generate's: a passphrase of Words words, or Length characters,
	// with symbols unless Symbols is false.
	Symbols    *bool  `json:"symbols,omitempty"`
	Separator  string `json:"separator,omitempty"`
	Length     int    `json:"length,omitempty"`
	Words      int    `json:"words,omitempty"`
	Capitalize bool   `json:"capitalize,omitempty"`
	Passphrase bool   `json:"passphrase,omitempty"`
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
	// fill's: the login's username, password, and current TOTP code;
	// generate's password, in Password.
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	TOTP     string `json:"totp,omitempty"`
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
	if errors.Is(err, tui.ErrLocked) {
		// The agent locked as the request was answered.
		err = errLocked
	}
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
	case "fill":
		return browserFill(req, reply)
	case "generate":
		return browserGenerate(req, reply)
	case "unlock_touchid":
		return browserUnlockTouchID(reply)
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
	msg = append(msg, body...)
	_, err = w.Write(msg)
	// A fill's reply holds a password: these copies of it go, at least.
	secure.SecureZeroBytes(body)
	secure.SecureZeroBytes(msg)
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

// errLocked is a request that needs the vault unlocked, refused while it
// isn't: the browser's sesh never asks for the master password.
var errLocked = &browserError{"locked", "sesh is locked: unlock it with Touch ID, or run any sesh command (or sesh ui) to unlock it"}

// openUnlocked opens the vault through the agent, when it's running and
// holds this vault's key, as this build: never asking for the master
// password, never reading SESH_MASTER_PASSWORD, and never starting an
// agent. The caller closes the store.
func openUnlocked() (*database.Store, error) {
	cfg, err := settings()
	if err != nil {
		return nil, err
	}
	dbPath := cfg.DBPath.Value
	mat, err := database.ReadUnlockMaterial(dbPath)
	if errors.Is(err, database.ErrNoVault) {
		return nil, noVault(dbPath)
	}
	if err != nil {
		return nil, err
	}
	conn, err := agent.DialExisting()
	if err != nil {
		return nil, errLocked
	}
	id := database.UnlockID(mat.Verify)
	if st, err := agent.Status(conn); err != nil || !agentUnlocks(&st, true, id) {
		closeAgentConn(conn)
		return nil, errLocked
	}
	store, err := openStoreWith(dbPath, agent.NewOracle(conn, id))
	if err != nil {
		return nil, uiLocked(err)
	}
	return store, nil
}

// browserFill gives the login req.ID names, for the tab at req.URL: its
// username, password, and current TOTP code when a TOTP entry with its
// name and username has one. The site is checked again here, whatever the
// extension found: one site's password is never given for another's
// page. Each secret read is recorded in the audit log, naming the site.
func browserFill(req *browserRequest, reply *browserReply) error {
	scheme, host, ok := sitematch.Of(req.URL)
	if !ok {
		return &browserError{"not_a_site", "sesh fills logins on http and https pages only"}
	}
	k, err := vault.ParseKey(req.ID)
	if err != nil || k.Kind != vault.KindPassword && k.Kind != vault.KindAPIKey {
		return &browserError{"bad_request", fmt.Sprintf("%q isn't a login sesh fills: a password or API key entry's ID", req.ID)}
	}
	store, err := openUnlocked()
	if err != nil {
		return err
	}
	defer closeAuditStore(store)
	// The site is checked on the row the secret is read from, at once, so
	// a rename or an edit meanwhile can't swap in another site's.
	e, secret, err := store.GetChecked(k, "secret, to fill it in on "+host, func(e *vault.Entry) error {
		if !slices.ContainsFunc(entryURLs(e), func(u string) bool { return sitematch.Matches(u, scheme, host) }) {
			return &browserError{"not_this_site", fmt.Sprintf("%s isn't for %s: sesh fills a login only on its own site", k, host)}
		}
		return nil
	})
	if errors.Is(err, vault.ErrNotFound) {
		return &browserError{"not_found", fmt.Sprintf("sesh has no %s now", k)}
	}
	if err != nil {
		return uiLocked(err)
	}
	defer secure.SecureZeroBytes(secret)
	reply.Username, reply.Password = e.Username, string(secret)
	code := vault.Key{Kind: vault.KindTOTP, Service: k.Service, Username: k.Username}
	c, key, err := store.GetChecked(code, "TOTP key, to fill its code in on "+host, func(*vault.Entry) error { return nil })
	switch {
	case errors.Is(err, vault.ErrNotFound):
	case err != nil:
		return uiLocked(err)
	default:
		defer secure.SecureZeroBytes(key)
		if reply.TOTP, err = totp.CodeAt(key, c.Settings.TOTP, time.Now()); err != nil {
			return fmt.Errorf("%s's code: %w", code, err)
		}
	}
	return nil
}

// browserGenerate makes a new password, or passphrase, as sesh generate
// does, with its defaults for what req leaves out; it's stored nowhere.
func browserGenerate(req *browserRequest, reply *browserReply) error {
	g := genFlags{length: 24, words: 6, separator: "-", noSymbols: req.Symbols != nil && !*req.Symbols, capped: req.Capitalize, passphrase: req.Passphrase}
	if req.Length != 0 {
		g.length = req.Length
	}
	if req.Words != 0 {
		g.words = req.Words
	}
	if req.Separator != "" {
		g.separator = req.Separator
	}
	// Said without the command line's flag names, which the popup hasn't.
	check := g.charOptions().Check
	if g.passphrase {
		check = g.wordOptions().Check
	}
	if err := check(); err != nil {
		return &browserError{"bad_request", err.Error()}
	}
	pw, err := g.generate()
	if err != nil {
		return err
	}
	defer secure.SecureZeroBytes(pw)
	reply.Password = string(pw)
	return nil
}

// browserUnlockTouchID unlocks the vault with a fingerprint, through the
// agent, as sesh ui's locked screen does: the system's Touch ID sheet
// shows. Only where Touch ID unlock is on and usable for this vault.
func browserUnlockTouchID(reply *browserReply) error {
	if !touchIDPlatform {
		return &browserError{"no_touch_id", "Touch ID unlock is only on macOS"}
	}
	cfg, err := settings()
	if err != nil {
		return err
	}
	dbPath := cfg.DBPath.Value
	mat, err := database.ReadUnlockMaterial(dbPath)
	if errors.Is(err, database.ErrNoVault) {
		return noVault(dbPath)
	}
	if err != nil {
		return err
	}
	// Nothing's started for a vault Touch ID can't unlock here.
	switch {
	case overSSH():
		return &browserError{"no_touch_id", "Touch ID isn't used over SSH: run any sesh command (or sesh ui) to unlock sesh with the master password"}
	case !touchIDUsable(dbPath, mat.Verify):
		return &browserError{"no_touch_id", "Touch ID unlock isn't on for this vault (sesh touchid enable turns it on), or your fingerprints changed since it was: run any sesh command (or sesh ui) to unlock sesh with the master password"}
	}
	conn, err := agent.EnsureAgent()
	if err != nil {
		return fmt.Errorf("sesh's agent can't be reached: %w", err)
	}
	defer closeAgentConn(conn)
	var said []string
	ok, err := tryTouchID(conn, filepath.Dir(dbPath), agent.UnlockID(mat.Verify), mat.Verify, true, func(format string, a ...any) {
		said = append(said, fmt.Sprintf(format, a...))
	})
	switch {
	case err != nil:
		return err
	case !ok && len(said) > 0:
		return &browserError{"not_unlocked", strings.Join(said, " ")}
	case !ok:
		return &browserError{"not_unlocked", "Touch ID didn't unlock sesh: run any sesh command (or sesh ui) to unlock it with the master password"}
	}
	locked := false
	reply.Locked = &locked
	return nil
}
