package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/bashhack/sesh/internal/config"
	"github.com/bashhack/sesh/internal/totp"
	"github.com/bashhack/sesh/internal/vault"
)

// framed is body as the browser sends it: its length, then itself.
func framed(body string) []byte {
	return append(binary.NativeEndian.AppendUint32(nil, uint32(len(body))), body...) //nolint:gosec // test bodies are short
}

// askHost runs sesh browser-host on in, and reads its reply.
func askHost(t *testing.T, in []byte) (browserReply, error) {
	t.Helper()
	app := agentTestApp()
	app.Stdin = bytes.NewReader(in)
	app.StdinIsTerminal = func() bool { return false }
	err := runBrowserHost(app, []string{"chrome-extension://abc/"})
	out := app.Stdout.(*bytes.Buffer).Bytes()
	var reply browserReply
	if err != nil || len(out) == 0 {
		return reply, err
	}
	body, rerr := readBrowserMessage(bytes.NewReader(out))
	if rerr != nil {
		t.Fatalf("the reply isn't a message: %v (%q)", rerr, out)
	}
	if err := json.Unmarshal(body, &reply); err != nil {
		t.Fatalf("the reply isn't JSON: %v (%q)", err, body)
	}
	return reply, nil
}

// A broken message is an error, with no reply; one that isn't a request
// sesh knows is a reply saying so.
func TestBrowserHost_Messages(t *testing.T) {
	setupRekeyEnv(t)
	useConfigFile(t, "")
	big := append(binary.NativeEndian.AppendUint32(nil, maxBrowserRequest+1), make([]byte, maxBrowserRequest+1)...)
	for name, tc := range map[string]struct {
		wantSub string
		in      []byte
	}{
		"nothing":       {"read the request's length", nil},
		"a short count": {"read the request's length", []byte{1, 0}},
		"empty":         {"the request is empty", framed("")},
		"too long":      {"more than any sesh reads", big},
		"cut short":     {"read the request", framed(`{"type":"status"}`)[:10]},
	} {
		if _, err := askHost(t, tc.in); err == nil || !strings.Contains(err.Error(), tc.wantSub) {
			t.Errorf("%s: %v, want %q", name, err, tc.wantSub)
		}
	}
	// Run as the browser runs it: through sesh's command word, hidden.
	h := newTestHarness()
	h.app.Stdin = bytes.NewReader(framed(`{"type":"status"}`))
	h.app.StdinIsTerminal = func() bool { return false }
	args := []string{"sesh", "browser-host", "chrome-extension://abc/"}
	if err := checkCommandWord(args); err != nil {
		t.Fatalf("the command word: %v", err)
	}
	run(h.app, args)
	if body, err := readBrowserMessage(bytes.NewReader(h.stdout.Bytes())); err != nil || !strings.Contains(string(body), `"code":"no_vault"`) {
		t.Errorf("run: %q, %v\n%s", body, err, h.stderr.String())
	}
	// At a terminal, it says what it's for, and waits for nothing.
	app := agentTestApp()
	app.StdinIsTerminal = func() bool { return true }
	if err := runBrowserHost(app, nil); err == nil || !strings.Contains(err.Error(), "started by the browser") {
		t.Errorf("at a terminal: %v", err)
	}
	for body, code := range map[string]string{
		`not json`:          "bad_request",
		`{"type":"launch"}`: "unknown_request",
		`{"type":"status"}`: "no_vault",
		`{"type":"match","url":"https://github.com"}`: "no_vault",
		`{"type":"match","url":"file:///etc/passwd"}`: "not_a_site",
	} {
		reply, err := askHost(t, framed(body))
		if err != nil || reply.Status != "error" || reply.Code != code || reply.Message == "" {
			t.Errorf("%s: %+v, %v; want error %s", body, reply, err, code)
		}
	}
	// No vault: where sesh looked is said, as the browser's sesh may not
	// have the shell's SESH_DB_PATH.
	cfg, err := settings()
	if err != nil {
		t.Fatal(err)
	}
	if reply, err := askHost(t, framed(`{"type":"status"}`)); err != nil || !strings.Contains(reply.Message, cfg.DBPath.Value) {
		t.Errorf("no vault doesn't say where: %q, %v", reply.Message, err)
	}
}

// browserSecret is k's secret in browserVault: each entry its own, so a
// fill shows whose it gave.
func browserSecret(k vault.Key) string {
	if k.Kind == vault.KindTOTP {
		return "JBSWY3DPEHPK3PXP"
	}
	return "pw for " + k.String()
}

// browserVault is a vault of logins with URLs, made with the master
// password, which is then taken away: the host never has it.
func browserVault(t *testing.T) {
	t.Helper()
	setupRekeyEnv(t)
	useConfigFile(t, "")
	t.Setenv("SESH_MASTER_PASSWORD", "browser-password-1234")
	store, err := openSQLiteStore()
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range []struct {
		k      string
		url    string
		fields []vault.Field
	}{
		{"password/github/alice", "https://github.com/login", nil},
		{"password/github/bob", "github.com", nil}, // no scheme: https
		{"totp/github/alice", "", nil},             // alice's code
		{"api_key/GitHub", "https://github.com:443", nil},
		{"password/gist/alice", "https://gist.github.com", nil}, // not a parent's
		{"password/plain/alice", "http://github.com", nil},      // http only
		{"password/other/alice", "https://other.example", []vault.Field{{Name: "url-2", Value: []byte("https://github.com")}}},
		{"password/hidden/alice", "https://other.example", []vault.Field{{Name: "url-3", Value: []byte("https://github.com"), Secret: true}}},
		{"password/notes/alice", "https://other.example", []vault.Field{{Name: "website", Value: []byte("https://github.com")}}},
		{"secure_note/github", "https://github.com", nil}, // not a login
	} {
		k, err := vault.ParseKey(e.k)
		if err != nil {
			t.Fatal(err)
		}
		if err := store.SaveWithDetails(&vault.Entry{Key: k}, []byte(browserSecret(k)), &vault.Details{URL: e.url, Fields: e.fields}); err != nil {
			t.Fatalf("%s: %v", e.k, err)
		}
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SESH_MASTER_PASSWORD", "")
}

// Matching is by scheme, host and port, a scheme's own port aside; plain
// url-N fields count; only password and API key entries are offered, with
// whether a code comes with each. It needs nothing unlocked.
func TestBrowserHost_Match(t *testing.T) {
	browserVault(t)
	reply, err := askHost(t, framed(`{"type":"match","url":"https://github.com/session?x=1"}`))
	if err != nil || reply.Status != "ok" {
		t.Fatalf("match: %+v, %v", reply, err)
	}
	var got []string
	for _, e := range *reply.Entries {
		s := e.ID
		if e.TOTP {
			s += " +code"
		}
		got = append(got, s)
	}
	want := []string{"api_key/GitHub", "password/github/alice +code", "password/github/bob", "password/other/alice"}
	if strings.Join(got, ", ") != strings.Join(want, ", ") {
		t.Errorf("matched %q, want %q", got, want)
	}
	reply, err = askHost(t, framed(`{"type":"match","url":"http://github.com/"}`))
	if err != nil || reply.Entries == nil || len(*reply.Entries) != 1 || (*reply.Entries)[0].ID != "password/plain/alice" {
		t.Errorf("an http page: %+v, %v", reply, err)
	}
	// None: an empty list, said.
	app := agentTestApp()
	app.Stdin = bytes.NewReader(framed(`{"type":"match","url":"https://nothing.example/"}`))
	app.StdinIsTerminal = func() bool { return false }
	if err := runBrowserHost(app, nil); err != nil {
		t.Fatal(err)
	}
	body, err := readBrowserMessage(app.Stdout.(*bytes.Buffer))
	var none map[string]any
	if err != nil || json.Unmarshal(body, &none) != nil || none["status"] != "ok" || none["entries"] == nil || len(none["entries"].([]any)) != 0 {
		t.Errorf("no logins: %s, %v", body, err)
	}
}

// Locked until the agent holds this vault's key; Touch ID only where it's
// set up.
func TestBrowserHost_Status(t *testing.T) {
	browserVault(t)
	was := touchIDPlatform
	t.Cleanup(func() { touchIDPlatform = was })
	touchIDPlatform = false
	reply, err := askHost(t, framed(`{"type":"status"}`))
	if err != nil || reply.Status != "ok" || reply.Locked == nil || !*reply.Locked || reply.TouchID == nil || *reply.TouchID {
		t.Fatalf("no agent: %+v, %v", reply, err)
	}
	startTestAgent(t)
	cfg, err := settings()
	if err != nil {
		t.Fatal(err)
	}
	ks, _, err := keySourceFromAgent(cfg.DBPath.Value, fixedPrompt("browser-password-1234"))
	if err != nil {
		t.Fatal(err)
	}
	closeKeySource(t, ks)
	if reply, err := askHost(t, framed(`{"type":"status"}`)); err != nil || reply.Locked == nil || *reply.Locked {
		t.Errorf("unlocked: %+v, %v", reply, err)
	}
}

// unlockForBrowser starts an agent and unlocks it for the browser vault,
// as a command at the terminal would.
func unlockForBrowser(t *testing.T) {
	t.Helper()
	startTestAgent(t)
	cfg, err := settings()
	if err != nil {
		t.Fatal(err)
	}
	ks, _, err := keySourceFromAgent(cfg.DBPath.Value, fixedPrompt("browser-password-1234"))
	if err != nil {
		t.Fatal(err)
	}
	closeKeySource(t, ks)
}

// A fill gives one login, its code too, only on its own site, and only
// with the agent unlocked: SESH_MASTER_PASSWORD is never used. Each read
// is in the audit log, naming the site.
func TestBrowserHost_Fill(t *testing.T) {
	browserVault(t)
	fill := func(id, page string) browserReply {
		t.Helper()
		reply, err := askHost(t, framed(`{"type":"fill","id":"`+id+`","url":"`+page+`"}`))
		if err != nil {
			t.Fatal(err)
		}
		return reply
	}
	t.Setenv("SESH_MASTER_PASSWORD", "browser-password-1234")
	if r := fill("password/github/alice", "https://github.com/login"); r.Code != "locked" || r.Password != "" {
		t.Fatalf("no agent, the password in the environment: %+v", r)
	}
	t.Setenv("SESH_MASTER_PASSWORD", "")
	// An agent running, but locked, and the password in the environment:
	// still locked.
	startTestAgent(t)
	t.Setenv("SESH_MASTER_PASSWORD", "browser-password-1234")
	if r := fill("password/github/alice", "https://github.com/login"); r.Code != "locked" || r.Password != "" {
		t.Fatalf("a locked agent, the password in the environment: %+v", r)
	}
	t.Setenv("SESH_MASTER_PASSWORD", "")
	unlockForBrowser(t)
	before := time.Now()
	r := fill("password/github/alice", "https://github.com/login")
	after := time.Now()
	codeAt := func(at time.Time) string {
		c, err := totp.CodeAt([]byte("JBSWY3DPEHPK3PXP"), totp.Params{}, at)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	if r.Status != "ok" || r.Username != "alice" || r.Password != "pw for password/github/alice" || r.TOTP != codeAt(before) && r.TOTP != codeAt(after) {
		t.Fatalf("fill: %+v", r)
	}
	if r := fill("password/github/bob", "https://github.com/"); r.Status != "ok" || r.Password != "pw for password/github/bob" || r.TOTP != "" {
		t.Errorf("no TOTP entry, no code: %+v", r)
	}
	if r := fill("password/other/alice", "https://github.com/"); r.Status != "ok" || r.Password != "pw for password/other/alice" {
		t.Errorf("by its url-2: %+v", r)
	}
	for id, code := range map[string]string{
		"password/gist/alice":  "not_this_site", // another site's
		"password/plain/alice": "not_this_site", // http only, on an https page
		"secure_note/github":   "bad_request",
		"totp/github/alice":    "bad_request",
		"password/gone/alice":  "not_found",
		"nonsense":             "bad_request",
	} {
		if r := fill(id, "https://github.com/"); r.Code != code || r.Password != "" {
			t.Errorf("%s: %+v, want %s", id, r, code)
		}
	}
	if r := fill("password/github/alice", "chrome://settings"); r.Code != "not_a_site" {
		t.Errorf("not a site: %+v", r)
	}
	log := mustRun(t, runAudit)
	for _, want := range []string{"secret, to fill it in on github.com", "TOTP key, to fill its code in on github.com"} {
		if !strings.Contains(log, want) {
			t.Errorf("the audit log lacks %q:\n%s", want, log)
		}
	}
	if strings.Contains(log, "password/gist/alice") {
		t.Errorf("a refused fill read a secret:\n%s", log)
	}
}

// generate makes a password or passphrase as sesh generate does; Touch ID
// unlock is refused where there's none.
func TestBrowserHost_GenerateAndTouchID(t *testing.T) {
	browserVault(t)
	if r, err := askHost(t, framed(`{"type":"generate"}`)); err != nil || r.Status != "ok" || len(r.Password) != 24 {
		t.Errorf("a password: %+v, %v", r, err)
	}
	if r, err := askHost(t, framed(`{"type":"generate","passphrase":true,"words":4,"separator":"."}`)); err != nil || strings.Count(r.Password, ".") != 3 {
		t.Errorf("a passphrase: %+v, %v", r, err)
	}
	if r, err := askHost(t, framed(`{"type":"generate","length":3}`)); err != nil || r.Code != "bad_request" || strings.Contains(r.Message, "--") {
		t.Errorf("too short, said without the command line's flags: %+v, %v", r, err)
	}
	if r, err := askHost(t, framed(`{"type":"generate","symbols":false,"length":40}`)); err != nil || len(r.Password) != 40 || strings.ContainsAny(r.Password, "!@#$%^&*()-_=+[]{};:,.<>/?") {
		t.Errorf("no symbols: %+v, %v", r, err)
	}
	was := touchIDPlatform
	t.Cleanup(func() { touchIDPlatform = was })
	touchIDPlatform = false
	if r, err := askHost(t, framed(`{"type":"unlock_touchid"}`)); err != nil || r.Code != "no_touch_id" {
		t.Errorf("no Touch ID: %+v, %v", r, err)
	}
	// On a Mac, Touch ID not on for this vault: refused, no agent started
	// (tests can't start one, so one would be an error).
	touchIDPlatform = true
	if r, err := askHost(t, framed(`{"type":"unlock_touchid"}`)); err != nil || r.Code != "no_touch_id" {
		t.Errorf("Touch ID off: %+v, %v", r, err)
	}
}

// With Touch ID on, the extension unlocks sesh with a fingerprint, and can
// then fill.
func TestBrowserHost_TouchIDUnlocks(t *testing.T) {
	startTestAgent(t)
	prompts, _ := softwareTouchID(t)
	useConfigFile(t, "")
	t.Setenv("SESH_MASTER_PASSWORD", "")
	t.Setenv(config.EnvDBPath, createVaultWithTouchID(t)) // locked, Touch ID on
	was := touchIDPlatform
	t.Cleanup(func() { touchIDPlatform = was })
	touchIDPlatform = true
	if r, err := askHost(t, framed(`{"type":"status"}`)); err != nil || r.Locked == nil || !*r.Locked || r.TouchID == nil || !*r.TouchID {
		t.Fatalf("locked, Touch ID on: %+v, %v", r, err)
	}
	if r, err := askHost(t, framed(`{"type":"unlock_touchid"}`)); err != nil || r.Status != "ok" || *prompts != 1 {
		t.Fatalf("unlock: %+v, %v; prompts %d", r, err, *prompts)
	}
	if r, err := askHost(t, framed(`{"type":"status"}`)); err != nil || r.Locked == nil || *r.Locked {
		t.Errorf("after the fingerprint: %+v, %v", r, err)
	}
	// Unlocked so, a fill gives the login.
	store, err := openSQLiteStore()
	if err != nil {
		t.Fatal(err)
	}
	k := vault.Key{Kind: vault.KindPassword, Service: "github", Username: "alice"}
	if err := store.SaveWithDetails(&vault.Entry{Key: k}, []byte("pw after touch"), &vault.Details{URL: "https://github.com"}); err != nil {
		t.Fatal(err)
	}
	closeAuditStore(store)
	if r, err := askHost(t, framed(`{"type":"fill","id":"password/github/alice","url":"https://github.com/"}`)); err != nil || r.Password != "pw after touch" {
		t.Errorf("fill after the fingerprint: %+v, %v", r, err)
	}
	t.Setenv("SSH_CONNECTION", "10.0.0.1 22 10.0.0.2 22")
	if r, err := askHost(t, framed(`{"type":"unlock_touchid"}`)); err != nil || r.Code != "no_touch_id" || !strings.Contains(r.Message, "over SSH") {
		t.Errorf("over SSH: %+v, %v", r, err)
	}
}
