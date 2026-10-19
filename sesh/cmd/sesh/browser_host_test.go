package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"

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
		if err := store.SaveWithDetails(&vault.Entry{Key: k}, []byte("JBSWY3DPEHPK3PXP"), &vault.Details{URL: e.url, Fields: e.fields}); err != nil {
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
	for _, e := range reply.Entries {
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
	if err != nil || len(reply.Entries) != 1 || reply.Entries[0].ID != "password/plain/alice" {
		t.Errorf("an http page: %+v, %v", reply, err)
	}
	reply, err = askHost(t, framed(`{"type":"match","url":"https://nothing.example/"}`))
	if err != nil || reply.Status != "ok" || len(reply.Entries) != 0 {
		t.Errorf("no logins: %+v, %v", reply, err)
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
