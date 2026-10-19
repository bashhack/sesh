package tui

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	tea "charm.land/bubbletea/v2"

	"github.com/bashhack/sesh/internal/secure"
	"github.com/bashhack/sesh/internal/vault"
)

// AWSSetup is sesh aws setup, as the app asks it: storing an AWS
// profile's MFA key, and the MFA device it's for.
type AWSSetup interface {
	// Profiles are the AWS CLI's profiles, to offer.
	Profiles() []string
	// Check checks profile ("" for the default) can be set up, as sesh aws
	// setup does before it asks for the key: the AWS CLI is there, the
	// name, how it signs in, and, for a profile with access keys, who it
	// signs in as, AWS asked. It reads nothing of the vault.
	Check(profile string) (AWSProfile, error)
	// Existing is the entry v has for profile already, nil for none, and
	// whether a key replaced is kept in its history.
	Existing(v Vault, profile string) (e *vault.Entry, keepsHistory bool, err error)
	// ReadKey is the MFA key typed, or an otpauth:// link's, refusing one
	// that doesn't make AWS's codes. The caller wipes both.
	ReadKey(typed []byte) ([]byte, error)
	// FromEntry is the key of the TOTP entry src, for k, refusing one that
	// doesn't make AWS's codes; the audit log records the read. The caller
	// wipes it.
	FromEntry(v Vault, src, k vault.Key) ([]byte, error)
	// Codes are the code key makes now, and the next.
	Codes(key []byte) (first, second string, err error)
	// Devices are the authenticator apps AWS lists for profile's user.
	Devices(profile string) ([]string, error)
	// CheckDevice says why arn can't be the MFA device of a profile
	// signing in to account ("" when it isn't known).
	CheckDevice(arn, account string) error
	// KeyOnly says what's kept of a setup that saved the key, at k, but
	// not its device, and what to do: why is why not. inHistory says the
	// key replaced is in the entry's history.
	KeyOnly(k vault.Key, inHistory bool, why error) string
}

// AWSProfile is a profile checked for setting up its MFA key.
type AWSProfile struct {
	// Existing is the entry sesh has for it already, nil for none.
	Existing *vault.Entry
	Profile  string // as sesh aws --profile names it; "" for the default
	// Kind is how it signs in: "" with an IAM user's access keys, whose
	// user Identity is, in Account; "aws login", "SSO", or "a role".
	Kind, Identity, Account string
	// Done is what's said once it's set up.
	Done string
	// KeepsHistory says a key replaced is kept in the entry's history.
	KeepsHistory bool
}

// How the AWS setup reads the key.
const (
	awsKeyPaste = "paste it (on AWS's page, Show secret key), or its otpauth:// link"
	awsKeyEntry = "a TOTP entry sesh has, for a device AWS has already"
)

// awsSetting is an AWS setup under way: the profile checked, its entry,
// and the key, held for the codes until they're given.
type awsSetting struct {
	p         AWSProfile
	k         vault.Key
	key       []byte
	fromEntry bool
	saved     bool // the key is in the vault
}

// wipe drops the key held.
func (st *awsSetting) wipe() {
	secure.SecureZeroBytes(st.key)
	st.key = nil
}

// Messages from the AWS setup, each about the form or panel that asked.
type (
	awsProfilesMsg struct {
		in    *input
		names []string
		epoch int
	}
	awsCheckedMsg struct {
		err   error
		f     *form
		p     AWSProfile
		totps []string // the TOTP entries that could give the key
		epoch int
	}
	// awsKeyMsg is the key read, from what was typed, a QR code, or an
	// entry, to save; filing is where it goes.
	awsKeyMsg struct {
		err       error
		f         *form
		st        *awsSetting
		folder    *string
		key       []byte
		tags      []string
		epoch     int
		fromEntry bool
	}
	awsKeySavedMsg struct {
		err   error
		f     *form
		st    *awsSetting
		epoch int
	}
	awsDevicesMsg struct {
		err     error
		ov      *overlay
		st      *awsSetting
		devices []string
		epoch   int
	}
	awsDeviceSavedMsg struct {
		err   error
		st    *awsSetting
		epoch int
	}
)

// awsProfileName is how a profile is named in what the setup says.
func awsProfileName(profile string) string {
	if profile == "" {
		return "the default profile"
	}
	return "profile " + profile
}

// endAWSSetup drops the setup under way, wiping its key.
func (m *Model) endAWSSetup() {
	if m.awsSet != nil {
		m.awsSet.wipe()
		m.awsSet = nil
	}
}

// openAWSSetup opens the AWS setup's first form: the profile, checked as
// sesh aws setup checks it.
func (m *Model) openAWSSetup() tea.Cmd {
	m.endAWSSetup()
	m.ov = nil
	profile := m.textInput("profile", m.awsProfile())
	profile.hint = "the AWS CLI profile, as sesh aws --profile names it; empty for the default profile"
	f := &form{title: "Set up AWS MFA", inputs: []*input{profile}, row: -1, enterDone: "check it",
		note: "Stores an AWS CLI profile's MFA key, as sesh aws setup does, for sesh aws to sign in with its codes."}
	setup, epoch := m.opts.AWSSetup, m.epoch
	f.submit = func() tea.Cmd {
		name := profile.value()
		f.saving, f.err, f.working = true, "", "Checking "+awsProfileName(name)+"…"
		// AWS is asked first, with the vault let go, so neither a lock
		// nor quitting waits for it; then what the vault has.
		var msg awsCheckedMsg
		read := m.read(func(v Vault, _ func() bool) tea.Msg {
			e, keeps, err := setup.Existing(v, name)
			if err != nil {
				return awsCheckedMsg{err: err, f: f, epoch: epoch}
			}
			msg.p.Existing, msg.p.KeepsHistory = e, keeps
			// The entries that could give the key, to offer; none when
			// they can't be listed.
			if found, _, err := v.Search(""); err == nil {
				for i := range found {
					if k := found[i].Key; k.Kind == vault.KindTOTP && k != vault.AWSKey(name) {
						msg.totps = append(msg.totps, k.String())
					}
				}
			}
			return nil
		})
		return func() tea.Msg {
			p, err := setup.Check(name)
			if err != nil {
				return awsCheckedMsg{err: err, f: f, epoch: epoch}
			}
			msg = awsCheckedMsg{p: p, f: f, epoch: epoch}
			if failed := read(); failed != nil {
				return failed
			}
			return msg
		}
	}
	f.focusInput(0)
	m.form = f
	return func() tea.Msg { return awsProfilesMsg{names: setup.Profiles(), in: profile, epoch: epoch} }
}

// awsChecked goes on from a profile checked: asking before replacing the
// key sesh has, then to the key's form.
func (m *Model) awsChecked(msg *awsCheckedMsg) tea.Cmd {
	if msg.epoch != m.epoch || m.v == nil || m.form != msg.f {
		return nil
	}
	f := msg.f
	f.saving, f.working = false, ""
	switch {
	case errors.Is(msg.err, ErrLocked):
		return m.lock(lockedReason(msg.err))
	case msg.err != nil:
		f.err = msg.err.Error()
		return nil
	}
	f.wipe()
	m.form = nil
	st := &awsSetting{p: msg.p, k: vault.AWSKey(msg.p.Profile)}
	m.awsSet = st
	if msg.p.Existing == nil {
		return m.awsKeyForm(st, msg.totps)
	}
	question := "sesh already has an MFA key for " + awsProfileName(msg.p.Profile) + ". Replace it? The key it has now is kept in the entry's history."
	if !msg.p.KeepsHistory {
		question = "sesh already has an MFA key for " + awsProfileName(msg.p.Profile) + ". Replace it? history.keep is 0, so the key it has now won't be kept: if AWS doesn't finish adding the new device, the old key is gone."
	}
	m.ov = m.confirm(nil, "Set up AWS MFA", question, func() tea.Cmd { return m.awsKeyForm(st, msg.totps) })
	m.ov.danger, m.ov.aws = !msg.p.KeepsHistory, st
	return nil
}

// awsSteps is what to do in AWS before the key is read, for a profile of
// kind.
func awsSteps(kind string) string {
	if kind == "SSO" {
		return "To add sesh as an MFA device, register an authenticator app where your sign-in's MFA devices are managed (for IAM Identity Center, the AWS access portal's MFA devices page), and leave its setup page open: sesh reads its key, then gives you the codes it asks for. Or use a TOTP entry sesh has, for a device AWS has already."
	}
	return "To add sesh as an MFA device, in the AWS console go to IAM, then Users, your user, and Security credentials; under Multi-factor authentication (MFA), choose Assign MFA device, name it, choose Authenticator app, and Next. Leave that page open, without choosing Add MFA yet: sesh reads its key, then gives you the two codes it asks for. Or use a TOTP entry sesh has, for a device AWS has already (imported from your phone, say)."
}

// awsKeyForm opens the form that reads the profile's MFA key, and files
// its entry.
func (m *Model) awsKeyForm(st *awsSetting, totps []string) tea.Cmd {
	m.ov = nil
	from := []string{awsKeyPaste}
	if m.opts.ScanQR != nil {
		from = append(from, totpScan)
	}
	if m.opts.ReadQRImage != nil {
		from = append(from, totpImage)
	}
	from = append(from, awsKeyEntry)
	source := &input{kind: inputChoice, label: "the key", choices: from}
	chosen := func() string { return source.choices[source.choice] }
	key := &input{kind: inputSecret, label: "MFA key, or otpauth:// link"}
	key.shown = func() bool { return chosen() == awsKeyPaste }
	image := m.textInput("image file", "")
	image.hint = "a screenshot of the QR code, PNG or JPEG: its full path, or from ~/"
	image.shown = func() bool { return chosen() == totpImage }
	entry := m.textInput("TOTP entry", "")
	entry.hint = "its ID, such as totp/aws-phone/alice: one making AWS's codes (6 digits every 30 seconds)"
	entry.shown = func() bool { return chosen() == awsKeyEntry }
	entry.offers = totps
	var folderWas string
	var tagsWere []string
	if e := st.p.Existing; e != nil {
		folderWas, tagsWere = e.Folder, e.Tags
	}
	folder := m.textInput("folder", folderWas)
	folder.offers = m.folderNames()
	tags := m.textInput("tags", strings.Join(tagsWere, ", "))
	tags.hint, tags.many, tags.offers = "separated by commas", true, m.tagNames()
	f := &form{title: "MFA key for " + awsProfileName(st.p.Profile), inputs: []*input{source, key, image, entry, folder, tags}, row: -1,
		note: awsSteps(st.p.Kind)}
	setup, epoch := m.opts.AWSSetup, m.epoch
	f.submit = func() tea.Cmd {
		var fo *string
		if v := folder.value(); v != folderWas || st.p.Existing == nil && v != "" {
			fo = &v
		}
		var tagList []string
		for t := range strings.SplitSeq(tags.value(), ",") {
			if t = strings.TrimSpace(t); t != "" && !slices.Contains(tagList, t) {
				tagList = append(tagList, t)
			}
		}
		done := func(raw []byte, fromEntry bool, err error) tea.Msg {
			return awsKeyMsg{key: raw, fromEntry: fromEntry, err: err, f: f, st: st, folder: fo, tags: tagList, epoch: epoch}
		}
		f.err = ""
		switch chosen() {
		case awsKeyPaste:
			if len(key.secret) == 0 {
				f.err = "Paste the MFA key AWS shows, or its otpauth:// link."
				return nil
			}
			typed := bytes.Clone(key.secret)
			f.saving, f.working = true, "Saving the key…"
			return func() tea.Msg {
				defer secure.SecureZeroBytes(typed)
				k, err := setup.ReadKey(typed)
				return done(k, false, err)
			}
		case totpScan:
			f.saving, f.working = true, "Select the area of the screen with the QR code (Esc there cancels)…"
			f.quitting = "Quitting once the screen capture ends: Esc on its crosshair cancels it."
			m.scanning = true
			scan := m.opts.ScanQR
			return func() tea.Msg {
				qr, err := scan()
				defer secure.SecureZeroBytes(qr.Link)
				if err != nil {
					return done(nil, false, fmt.Errorf("no QR code read: %w", err))
				}
				k, err := setup.ReadKey(qr.Link)
				return done(k, false, err)
			}
		case totpImage:
			path := image.value()
			if path == "" {
				f.err = "Give the image file with the QR code."
				return nil
			}
			f.saving, f.working = true, "Reading the QR code…"
			read := m.opts.ReadQRImage
			return func() tea.Msg {
				qr, err := read(path)
				defer secure.SecureZeroBytes(qr.Link)
				if err != nil {
					return done(nil, false, fmt.Errorf("no QR code read: %w", err))
				}
				k, err := setup.ReadKey(qr.Link)
				return done(k, false, err)
			}
		}
		src, err := vault.ParseKey(entry.value())
		if err != nil || src.Kind != vault.KindTOTP {
			f.err = "Give a TOTP entry's ID, such as totp/aws-phone/alice."
			return nil
		}
		f.saving, f.working = true, "Reading "+src.String()+"'s key…"
		return m.read(func(v Vault, _ func() bool) tea.Msg {
			k, err := setup.FromEntry(v, src, st.k)
			return done(k, true, err)
		})
	}
	f.focusInput(0)
	m.form = f
	return nil
}

// awsKeyRead saves the key read, before AWS is told of it, so nothing
// that goes wrong after can lose a key AWS has started using.
func (m *Model) awsKeyRead(msg *awsKeyMsg) tea.Cmd {
	m.scanning = false
	switch {
	case m.quitAfter:
		secure.SecureZeroBytes(msg.key)
		return tea.Quit
	case msg.epoch != m.epoch || m.v == nil || m.form != msg.f || m.awsSet != msg.st:
		secure.SecureZeroBytes(msg.key)
		return nil
	}
	f, st := msg.f, msg.st
	f.quitting = ""
	switch {
	case errors.Is(msg.err, ErrLocked):
		return m.lock(lockedReason(msg.err))
	case msg.err != nil:
		f.saving, f.working = false, ""
		f.err = "Not saved: " + msg.err.Error()
		return nil
	}
	// From here the key may be in the vault: a lock says so.
	st.key, st.fromEntry, st.saved = msg.key, msg.fromEntry, true
	c := &Change{To: st.k, Secret: bytes.Clone(msg.key), Folder: msg.folder, Tags: msg.tags, TagsSet: true}
	if st.p.Existing != nil {
		// The device is found again, for the new key.
		none := ""
		c.Key, c.MFADevice = st.k, &none
	}
	epoch := m.epoch
	read := m.read(func(v Vault, _ func() bool) tea.Msg {
		_, err := v.Save(c)
		return awsKeySavedMsg{err: err, f: f, st: st, epoch: epoch}
	})
	return func() tea.Msg {
		defer c.Wipe() // saved, or not: the app locked before the save began
		return read()
	}
}

// awsKeySaved goes on to the codes AWS asks for, once the key's saved.
func (m *Model) awsKeySaved(msg *awsKeySavedMsg) tea.Cmd {
	if msg.epoch != m.epoch || m.v == nil || m.form != msg.f || m.awsSet != msg.st {
		return nil
	}
	f, st := msg.f, msg.st
	f.saving, f.working = false, ""
	switch {
	case errors.Is(msg.err, ErrLocked):
		return m.lock(lockedReason(msg.err))
	case msg.err != nil:
		st.wipe()
		st.saved = false
		f.err = "Not saved: " + msg.err.Error()
		return nil
	}
	f.wipe()
	m.form = nil
	m.forget(st.k)
	reread := m.reread()
	if st.fromEntry {
		// A device AWS has already: no codes to give it.
		return tea.Batch(reread, m.awsAfterCodes(st))
	}
	m.awsCodes(st)
	return reread
}

// awsCodes shows the codes AWS asks for, made now.
func (m *Model) awsCodes(st *awsSetting) {
	first, second, err := m.opts.AWSSetup.Codes(st.key)
	if err != nil {
		st.wipe()
		m.endAWSSetup()
		m.ov = &overlay{kind: panelNotice, title: "Set up AWS MFA", question: "The codes couldn't be made: " + err.Error() + "\n\nThe MFA key is saved, as " + st.k.String() + "."}
		return
	}
	said := "The two codes AWS asks for:\n\n   MFA code 1:  " + first + "\n   MFA code 2:  " + second + "\n\nEnter them, choose Add MFA, and wait for AWS to say the device was added."
	if st.p.Kind == "SSO" {
		said = "The code, and the next, for the page:\n\n   " + first + ", then " + second + "\n\nEnter what it asks for, and finish adding the device there."
	}
	m.ov = &overlay{kind: panelAWSCodes, title: "AWS MFA codes for " + awsProfileName(st.p.Profile), question: said, aws: st}
}

// awsLeft is what's said of a setup left once the key was saved.
func (m *Model) awsLeft(st *awsSetting, why string) *overlay {
	said := "The MFA key is saved, as " + st.k.String() + ": finish adding the device in AWS."
	if st.p.Kind == "" {
		said = m.opts.AWSSetup.KeyOnly(st.k, st.p.Existing != nil && st.p.KeepsHistory, errors.New(why))
	}
	return &overlay{kind: panelNotice, title: "Set up AWS MFA", question: said}
}

// awsCodesKey handles a key over the codes: Enter once AWS has the
// device, n for new codes, Esc to leave the setup.
func (m *Model) awsCodesKey(k string) tea.Cmd {
	st := m.awsSet
	if st == nil {
		m.ov = nil
		return nil
	}
	switch k {
	case "enter":
		return m.awsAfterCodes(st)
	case "n":
		m.awsCodes(st)
	case "esc":
		m.ov = m.awsLeft(st, "Left before AWS had the device")
		m.endAWSSetup()
	}
	return nil
}

// awsAfterCodes finishes the setup once AWS has the device: a profile
// with access keys has its device found, which sesh aws asks AWS for a
// session with; another is done.
func (m *Model) awsAfterCodes(st *awsSetting) tea.Cmd {
	st.wipe()
	if st.p.Kind != "" {
		m.endAWSSetup()
		m.ov = &overlay{kind: panelNotice, title: "Set up AWS MFA", question: st.p.Done}
		return nil
	}
	return m.awsListDevices(st)
}

// awsListDevices asks AWS for the user's authenticator apps, to choose
// the one just added from.
func (m *Model) awsListDevices(st *awsSetting) tea.Cmd {
	ov := &overlay{kind: panelMenu, title: "MFA device for " + awsProfileName(st.p.Profile), loading: true, busy: "Asking AWS for the user's authenticator apps…",
		back: m.awsLeft(st, "No MFA device was chosen"), aws: st}
	m.ov = ov
	setup, epoch, profile := m.opts.AWSSetup, m.epoch, st.p.Profile
	return func() tea.Msg {
		devices, err := setup.Devices(profile)
		return awsDevicesMsg{devices: devices, err: err, ov: ov, st: st, epoch: epoch}
	}
}

// awsDevices lists the devices AWS has, to choose from, or type.
func (m *Model) awsDevices(msg *awsDevicesMsg) tea.Cmd {
	if msg.epoch != m.epoch || m.v == nil || m.ov != msg.ov || m.awsSet != msg.st {
		return nil
	}
	ov, st := msg.ov, msg.st
	ov.loading, ov.busy = false, ""
	ov.items = nil
	for i, d := range msg.devices {
		it := item{label: d, does: "choose", run: func() tea.Cmd { return m.awsSaveDevice(st, d) }}
		if i < 9 {
			it.key = strconv.Itoa(i + 1)
		}
		ov.items = append(ov.items, it)
	}
	again := item{key: "r", label: "look again", rule: len(msg.devices) > 0, stay: true, run: func() tea.Cmd { return m.awsListDevices(st) }}
	switch {
	case msg.err != nil:
		again.detail = "sesh couldn't list the user's MFA devices: " + msg.err.Error()
	case len(msg.devices) == 0:
		again.detail = "AWS lists no authenticator app for this user yet; it can take a few seconds after Add MFA."
	default:
		again.detail = "Choose the one you just added."
	}
	ov.items = append(ov.items, again, item{key: "m", label: "type its ARN…", run: func() tea.Cmd { return m.awsDeviceForm(st) }})
	ov.sel = 0
	if len(msg.devices) == 0 {
		ov.sel = len(ov.items) - 2 // look again, which says why
	}
	return nil
}

// awsDeviceForm asks for the device's ARN, as it's shown in AWS.
func (m *Model) awsDeviceForm(st *awsSetting) tea.Cmd {
	example := "arn:aws:iam::ACCOUNT:mfa/NAME"
	if st.p.Account != "" {
		example = "arn:aws:iam::" + st.p.Account + ":mfa/NAME"
	}
	arn := m.textInput("MFA device ARN", "")
	arn.hint = "as the user's Security credentials page shows it, under MFA: " + example
	back := m.ov
	m.ov = nil
	f := &form{title: "MFA device for " + awsProfileName(st.p.Profile), inputs: []*input{arn}, row: -1, enterDone: "save it"}
	f.cancel = func() { m.ov = back }
	f.submit = func() tea.Cmd {
		if err := m.opts.AWSSetup.CheckDevice(arn.value(), st.p.Account); err != nil {
			f.err = err.Error()
			return nil
		}
		f.wipe()
		m.form = nil
		return m.awsSaveDevice(st, arn.value())
	}
	f.focusInput(0)
	m.form = f
	return nil
}

// awsSaveDevice saves the device chosen with the key.
func (m *Model) awsSaveDevice(st *awsSetting, device string) tea.Cmd {
	m.ov = &overlay{kind: panelNotice, title: "Set up AWS MFA", loading: true, question: "Saving the MFA device…", aws: st}
	epoch := m.epoch
	return m.read(func(v Vault, _ func() bool) tea.Msg {
		_, err := v.Save(&Change{Key: st.k, To: st.k, MFADevice: &device})
		return awsDeviceSavedMsg{err: err, st: st, epoch: epoch}
	})
}

// awsDeviceSaved ends the setup, saying it's done, or what's kept.
func (m *Model) awsDeviceSaved(msg *awsDeviceSavedMsg) tea.Cmd {
	if msg.epoch != m.epoch || m.v == nil || m.awsSet != msg.st {
		return nil
	}
	st := msg.st
	if errors.Is(msg.err, ErrLocked) {
		return m.lock(lockedReason(msg.err))
	}
	m.endAWSSetup()
	if msg.err != nil {
		m.ov = m.awsLeft(st, "The MFA device wasn't saved: "+msg.err.Error())
		return nil
	}
	m.forget(st.k)
	m.ov = &overlay{kind: panelNotice, title: "Set up AWS MFA", question: st.p.Done}
	return m.reread()
}
