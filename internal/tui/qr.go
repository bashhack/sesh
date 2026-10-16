package tui

import (
	"strconv"
	"strings"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"github.com/bashhack/sesh/internal/qrcode"
	"github.com/bashhack/sesh/internal/secure"
	"github.com/bashhack/sesh/internal/totp"
	"github.com/bashhack/sesh/internal/vault"
)

// qrMsg is a TOTP key drawn as a QR code, or why it wasn't.
type qrMsg struct {
	err   error
	link  string
	qr    string
	k     vault.Key
	epoch int
}

// openQR shows TOTP entry e's key as a QR code, for an authenticator app
// on a phone: a read the audit log records.
func (m *Model) openQR(e *vault.Entry) tea.Cmd {
	k, epoch := e.Key, m.epoch
	issuer, account := totp.Label(e.Service, e.Username, e.Settings.TOTP)
	params := e.Settings.TOTP
	m.ov = &overlay{kind: panelQR, back: m.ov, title: "Key of " + entryName(e), k: k, loading: true,
		question: "Scan it with the authenticator app: it adds " + totp.LabelName(issuer, account) + ". The code is the key; close it once it's scanned."}
	return m.read(func(v Vault, _ func() bool) tea.Msg {
		secret, err := v.Secret(k, "in sesh ui, to show its key as a QR code")
		if err != nil {
			return qrMsg{err: err, k: k, epoch: epoch}
		}
		defer secure.SecureZeroBytes(secret)
		link := totp.URI(secret, issuer, account, params)
		drawn, err := qrcode.Terminal(link)
		return qrMsg{err: err, link: link, qr: drawn, k: k, epoch: epoch}
	})
}

// shownQR puts the QR code read into its panel, still open on its entry.
func (m *Model) shownQR(msg *qrMsg) tea.Cmd {
	if msg.epoch != m.epoch || m.ov == nil || m.ov.kind != panelQR || m.ov.k != msg.k {
		return nil
	}
	ov := m.ov
	ov.loading = false
	if msg.err != nil {
		ov.err = "Couldn't show it: " + msg.err.Error()
		return nil
	}
	ov.qr, ov.link = strings.Split(strings.TrimSuffix(msg.qr, "\n"), "\n"), msg.link
	return nil
}

// qrLines are the QR panel's lines, w wide at most, room high: the code
// and what to do with it, or, where it doesn't fit, how big a window it
// needs.
func (m *Model) qrLines(ov *overlay, w, room int) []string {
	th := m.th
	said := strings.Split(th.style().Width(w-6).Render(ov.question), "\n")
	codeWidth := lipgloss.Width(ov.qr[0])
	if codeWidth > w-6 || len(ov.qr)+len(said)+1 > room {
		return append([]string{""}, strings.Split(th.dimmed().Width(w-6).Render(
			"The window is too small for the QR code: it needs about "+strconv.Itoa(codeWidth+8)+" columns and "+strconv.Itoa(len(ov.qr)+len(said)+9)+" rows. c copies the otpauth:// link instead."), "\n")...)
	}
	lines := append([]string{""}, ov.qr...)
	return append(append(lines, ""), said...)
}

// copyLink copies the open QR panel's otpauth:// link.
func (m *Model) copyLink(ov *overlay) tea.Cmd {
	link, opts, epoch := ov.link, m.opts, m.epoch
	return func() tea.Msg {
		if err := opts.Copy(link); err != nil {
			return copiedMsg{what: "Couldn't copy: " + err.Error(), epoch: epoch, bad: true}
		}
		return copiedMsg{what: copied("the otpauth:// link", opts.ClearAfter), epoch: epoch}
	}
}
