package tui

import (
	"errors"

	tea "charm.land/bubbletea/v2"

	"github.com/bashhack/sesh/internal/vault"
)

// awsSignedInMsg is a sign-in to AWS taken as far as it goes with the app
// open: the shell to open once the app has ended, or why not. on is the
// panel that waits for it.
type awsSignedInMsg struct {
	err   error
	shell func(release func()) error
	on    *overlay
	epoch int
}

// isAWSEntry says whether e is an AWS profile's MFA entry,
// totp/aws/<profile>.
func isAWSEntry(e *vault.Entry) bool { return e.Key == vault.AWSKey(e.Username) }

// awsSignIn signs in to AWS with the profile e is the MFA entry of, as
// sesh aws does, over a panel that waits for it (Esc leaves it, and the
// app stays); once it's signed in, the app ends, and the shell opens.
func (m *Model) awsSignIn(e *vault.Entry) tea.Cmd {
	k, epoch, sign := e.Key, m.epoch, m.opts.AWSSignIn
	ov := &overlay{kind: panelNotice, title: "AWS: profile " + e.Username, loading: true,
		question: "Signing in to AWS, as sesh aws does… Esc leaves it, and the app stays open."}
	m.ov = ov
	// What the sign-in reads of the vault is read with it open; the
	// sign-in itself, talking to AWS, runs with it let go, so neither a
	// lock nor quitting waits for AWS.
	var signIn func() (func(func()) error, error)
	read := m.read(func(v Vault, _ func() bool) tea.Msg {
		s, err := sign(v, k)
		if err != nil {
			return awsSignedInMsg{err: err, on: ov, epoch: epoch}
		}
		signIn = s
		return nil
	})
	return func() tea.Msg {
		if msg := read(); msg != nil || signIn == nil {
			return msg
		}
		shell, err := signIn()
		return awsSignedInMsg{err: err, shell: shell, on: ov, epoch: epoch}
	}
}

// awsSignedIn ends the app for the shell, or says why it isn't signed in.
// A sign-in whose panel is gone (left with Esc, or locked meanwhile)
// opens nothing.
func (m *Model) awsSignedIn(msg *awsSignedInMsg) tea.Cmd {
	if msg.epoch != m.epoch || m.v == nil || m.ov != msg.on {
		return nil
	}
	switch {
	case errors.Is(msg.err, ErrLocked):
		return m.lock(lockedReason(msg.err))
	case msg.err != nil:
		msg.on.loading, msg.on.question = false, "Not signed in: "+msg.err.Error()
		return nil
	}
	m.then = msg.shell
	return tea.Quit
}

// Then is what the app has left to do once it has ended: the AWS shell to
// open, with release to call once the shell no longer needs the vault;
// nil when nothing.
func (m *Model) Then() func(release func()) error { return m.then }
