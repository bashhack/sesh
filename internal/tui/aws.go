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
	shell AWSShell
	on    *overlay
	epoch int
}

// The AWS sign-in's steps: the shell it opens once the app has ended,
// with release to call once the shell no longer needs the vault; the
// sign-in that gives it, run with the vault let go; and what it reads of
// the vault first, which gives the sign-in.
type (
	AWSShell      = func(release func()) error
	AWSSignInStep = func() (AWSShell, error)
	AWSVaultStep  = func(v Vault) (AWSSignInStep, error)
)

// isAWSEntry says whether e is an AWS profile's MFA entry,
// totp/aws/<profile>.
func isAWSEntry(e *vault.Entry) bool { return e.Key == vault.AWSKey(e.Username) }

// awsSignIn signs in to AWS with the profile e is the MFA entry of, as
// sesh aws does, over a panel that waits for it (Esc leaves it, and the
// app stays); once it's signed in, the app ends, and the shell opens.
func (m *Model) awsSignIn(e *vault.Entry) tea.Cmd { return m.awsSignInAs(e.Key) }

// awsSignInAs signs in with the profile whose MFA entry is, or would be,
// k, as awsSignIn does.
func (m *Model) awsSignInAs(k vault.Key) tea.Cmd {
	epoch, sign := m.epoch, m.opts.AWSSignIn
	ov := &overlay{kind: panelNotice, title: "AWS: " + awsProfileName(profileOf(k)), loading: true,
		question: "Signing in to AWS, as sesh aws does… Esc leaves it, and the app stays open."}
	m.ov = ov
	// How the profile signs in is found with the vault let go (it may ask
	// the AWS CLI); what the sign-in needs of the vault, with it open; and
	// the sign-in itself, talking to AWS, with it let go again, so neither
	// a lock nor quitting waits for AWS.
	var vaultStep AWSVaultStep
	var signIn AWSSignInStep
	read := m.read(func(v Vault, _ func() bool) tea.Msg {
		s, err := vaultStep(v)
		if err != nil {
			return awsSignedInMsg{err: err, on: ov, epoch: epoch}
		}
		signIn = s
		return nil
	})
	return func() tea.Msg {
		var err error
		if vaultStep, err = sign(k); err != nil {
			return awsSignedInMsg{err: err, on: ov, epoch: epoch}
		}
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

// profileOf is the AWS profile whose MFA entry is k, "" for the default.
func profileOf(k vault.Key) string {
	if k == vault.AWSKey("") {
		return ""
	}
	return k.Username
}

// awsProfile is the profile the AWS forms start with.
func (m *Model) awsProfile() string {
	if m.opts.AWSProfile == nil {
		return ""
	}
	return m.opts.AWSProfile()
}

// openAWSSignIn asks which AWS CLI profile to sign in with, as sesh aws
// --profile does, whether or not sesh has an MFA key for it.
func (m *Model) openAWSSignIn() tea.Cmd {
	m.ov = nil
	profile := m.textInput("profile", m.awsProfile())
	profile.start = profile.value()
	profile.hint = "the AWS CLI profile, as sesh aws --profile names it; empty for the default profile"
	f := &form{title: "Sign in to AWS", inputs: []*input{profile}, row: -1, enterDone: "sign in",
		note: "Signs in with an AWS CLI profile, as sesh aws does, and opens a shell with it once the app ends. A profile with an IAM user's access keys needs its MFA key in sesh (set up AWS MFA… stores one); one that signs in with aws login or SSO doesn't, but without it nothing is copied: if the sign-in asks for an MFA code, it's your MFA device's."}
	f.submit = func() tea.Cmd {
		if err := vault.CheckName("AWS profile", profile.value()); err != nil {
			f.err = err.Error()
			return nil
		}
		k := vault.AWSKey(profile.value())
		f.wipe()
		m.form = nil
		return m.awsSignInAs(k)
	}
	f.focusInput(0)
	m.form = f
	if setup := m.opts.AWSSetup; setup != nil {
		epoch := m.epoch
		return func() tea.Msg { return awsProfilesMsg{names: setup.Profiles(), in: profile, epoch: epoch} }
	}
	return nil
}

// Then is what the app has left to do once it has ended: the AWS shell to
// open, with release to call once the shell no longer needs the vault;
// nil when nothing.
func (m *Model) Then() func(release func()) error { return m.then }
