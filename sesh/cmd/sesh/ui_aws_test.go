package main

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/bashhack/sesh/internal/aws"
	"github.com/bashhack/sesh/internal/aws/mocks"
	"github.com/bashhack/sesh/internal/config"
	awsProvider "github.com/bashhack/sesh/internal/provider/aws"
	"github.com/bashhack/sesh/internal/totp"
	"github.com/bashhack/sesh/internal/vault"
)

// fakeSTS is AWS as the app's sign-in sees it, for profiles with access
// keys: each session asked for, by profile, and what AWS says.
type fakeSTS struct {
	err      error
	profiles []string
	mu       sync.Mutex
}

// stubSTS has sesh aws's sign-in ask f for sessions, and take profiles to
// be of kind.
func stubSTS(t *testing.T, f *fakeSTS, kind string) {
	t.Helper()
	was, wasKind := newAWSProvider, awsProfileKind
	t.Cleanup(func() { newAWSProvider, awsProfileKind = was, wasKind })
	awsProfileKind = func(string) string { return kind }
	newAWSProvider = func(store vault.Store) *awsProvider.Provider {
		return awsProvider.NewProvider(&mocks.MockProvider{
			GetFirstMFADeviceFunc: func(string) (string, error) { return "arn:aws:iam::123456789012:mfa/me", nil },
			GetSessionTokenFunc: func(profile, _ string, _ []byte) (aws.Credentials, error) {
				f.mu.Lock()
				defer f.mu.Unlock()
				f.profiles = append(f.profiles, profile)
				if f.err != nil {
					return aws.Credentials{}, f.err
				}
				return aws.Credentials{AccessKeyID: "ASIAFAKE", SecretAccessKey: "s", SessionToken: "t", Expiration: "2030-01-01T00:00:00Z"}, nil
			},
		}, store, totp.NewDefaultProvider())
	}
}

// awsVault is a vault with MFA keys for profile work and the default
// profile.
func awsVault(t *testing.T) {
	t.Helper()
	env := setupRekeyEnv(t)
	useConfigFile(t, "")
	t.Setenv("SESH_MASTER_PASSWORD", "aws-password-1234")
	t.Setenv("SESH_ACTIVE", "")
	populatePasswordStore(t, env, map[string]string{"totp/aws/work": "JBSWY3DPEHPK3PXP", "totp/aws/default": "JBSWY3DPEHPK3PXP"})
}

// The app's sign-in: a profile with access keys gets its session with the
// app open (the default profile as sesh aws without --profile), and AWS
// refusing is said; a role, or a shell sesh opened, is refused; aws login
// is left to once the app has ended.
func TestUI_AWSSignIn(t *testing.T) {
	awsVault(t)
	f := &fakeSTS{}
	stubSTS(t, f, "")
	store, err := openSQLiteStore()
	if err != nil {
		t.Fatal(err)
	}
	u := newUIVault(store)
	defer u.Close() //nolint:errcheck // test cleanup
	app := agentTestApp()
	for _, k := range []vault.Key{vault.AWSKey("work"), vault.AWSKey("")} {
		shell, err := uiAWSSignIn(app, u, k)
		if err != nil || shell == nil {
			t.Fatalf("%s: %v", k, err)
		}
	}
	if len(f.profiles) != 2 || f.profiles[0] != "work" || f.profiles[1] != "" {
		t.Errorf("sessions asked for %q, want work and the default profile", f.profiles)
	}
	f.err = errors.New("aws sts get-session-token: AccessDenied")
	if shell, err := uiAWSSignIn(app, u, vault.AWSKey("work")); shell != nil || err == nil || !strings.Contains(err.Error(), "AccessDenied") {
		t.Errorf("AWS refusing: %v", err)
	}
	stubSTS(t, f, aws.KindRole)
	if _, err := uiAWSSignIn(app, u, vault.AWSKey("work")); err == nil || !strings.Contains(err.Error(), "assumes a role") {
		t.Errorf("a role: %v", err)
	}
	stubSTS(t, f, aws.KindLogin)
	f.profiles = nil
	if shell, err := uiAWSSignIn(app, u, vault.AWSKey("work")); err != nil || shell == nil || len(f.profiles) != 0 {
		t.Errorf("aws login: %v; sessions asked for %q", err, f.profiles)
	}
	t.Setenv("SESH_ACTIVE", "1")
	if _, err := uiAWSSignIn(app, u, vault.AWSKey("work")); err == nil || !strings.Contains(err.Error(), "shell sesh opened") {
		t.Errorf("in a sesh shell: %v", err)
	}
}

// lockSeen is stderr, noting whether the shell had started when
// ui.lock_on_quit locked sesh.
type lockSeen struct {
	mark  string // the file the shell writes
	said  strings.Builder
	mu    sync.Mutex
	early bool // locked before the shell started
}

func (w *lockSeen) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if strings.Contains(string(p), "Locked sesh") {
		_, err := os.Stat(w.mark)
		w.early = errors.Is(err, os.ErrNotExist)
	}
	return w.said.Write(p)
}

// From the app, Ctrl-K a signs in, the app ends, sesh locks
// (ui.lock_on_quit), and then the shell opens with the session.
func TestUI_RunAWSShell(t *testing.T) {
	awsVault(t)
	startTestAgent(t)
	cfg, err := settings()
	if err != nil {
		t.Fatal(err)
	}
	ks, _, err := keySourceFromAgent(cfg.DBPath.Value, fixedPrompt("aws-password-1234"))
	if err != nil {
		t.Fatal(err)
	}
	closeKeySource(t, ks)
	t.Setenv(config.EnvUILockOnQuit, "true")
	stubSTS(t, &fakeSTS{}, "")
	dir := t.TempDir()
	mark, shell := filepath.Join(dir, "shell ran"), filepath.Join(dir, "sh")
	if err := os.WriteFile(shell, []byte("#!/bin/sh\nprintf '%s' \"$AWS_ACCESS_KEY_ID\" > \"$SHELL_MARK\"\n"), 0o700); err != nil { //nolint:gosec // a test shell
		t.Fatal(err)
	}
	t.Setenv("SHELL", shell)
	t.Setenv("SHELL_MARK", mark)
	oldTerm, oldOpts := uiStdoutIsTerminal, uiProgramOptions
	t.Cleanup(func() { uiStdoutIsTerminal, uiProgramOptions = oldTerm, oldOpts })
	uiStdoutIsTerminal = func(io.Writer) bool { return true }
	var screen syncBuffer
	uiProgramOptions = []tea.ProgramOption{tea.WithWindowSize(80, 24), tea.WithFilter(func(m tea.Model, msg tea.Msg) tea.Msg {
		if v, ok := m.(interface{ View() tea.View }); ok {
			screen.mu.Lock()
			screen.b.Reset()
			screen.b.WriteString(ansi.Strip(v.View().Content))
			screen.mu.Unlock()
		}
		return msg
	})}
	in, keys := io.Pipe()
	app := agentTestApp()
	stderr := &lockSeen{mark: mark}
	app.Stdin, app.Stdout, app.Stderr = in, &syncBuffer{}, stderr
	app.StdinIsTerminal = func() bool { return true }
	done := make(chan error, 1)
	go func() { done <- runUI(app, nil) }()
	send := func(k string) {
		if _, err := keys.Write([]byte(k)); err != nil {
			t.Fatal(err)
		}
	}
	waitFor(t, "every entry", func() bool { return strings.Contains(screen.String(), "2 entries") })
	send("work")
	waitFor(t, "the search", func() bool { return strings.Contains(screen.String(), "1 of 2") })
	send("\x0b")
	waitFor(t, "the menu", func() bool { return strings.Contains(screen.String(), "sign in to AWS and open a shell") })
	send("a")
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("sesh ui: %v\n%s", err, stderr.said.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("sesh ui didn't end:\n%s", screen.String())
	}
	if got, err := os.ReadFile(mark); err != nil || string(got) != "ASIAFAKE" { //nolint:gosec // the test's own file
		t.Errorf("the shell had %q (%v), want the session's key", got, err)
	}
	if !stderr.early {
		t.Errorf("sesh wasn't locked before the shell started:\n%s", stderr.said.String())
	}
}
