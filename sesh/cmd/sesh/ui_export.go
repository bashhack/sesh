package main

import (
	"errors"
	"fmt"

	"github.com/bashhack/sesh/internal/exportfile"
	"github.com/bashhack/sesh/internal/password"
	"github.com/bashhack/sesh/internal/secure"
	"github.com/bashhack/sesh/internal/tui"
)

// Export writes an encrypted export of every entry to the file to names,
// as sesh --action export --format encrypted does, with pw, which it
// wipes; a file there is replaced only when replace.
func (u *uiVault) Export(to string, pw []byte, replace bool) (string, error) {
	defer secure.SecureZeroBytes(pw)
	dest, err := uiPath(to)
	if err != nil {
		return "", err
	}
	out, err := exportfile.Open(dest, replace, u.store.Path())
	if exists := (*exportfile.ExistsError)(nil); errors.As(err, &exists) {
		return "", tui.Exists(tildePath(dest) + " already exists.")
	}
	if err != nil {
		return "", err
	}
	defer out.Abort()
	// As Open found it, through any link: sesh ui has the terminal.
	if out.Device() {
		return "", errors.New("export to a file: sesh ui has the terminal, so a device or pipe isn't written to here")
	}
	st, err := settings()
	if err != nil {
		return "", err
	}
	if err := out.Start(); err != nil {
		return "", fmt.Errorf("can't write an export there: %w", err)
	}
	// On a connection of its own: an export reads every entry, which on
	// the store's one connection would hold up everything else the app does.
	r, err := u.store.Reader()
	if err != nil {
		return "", uiLocked(err)
	}
	defer r.Close() //nolint:errcheck // read only, but for the audit events
	n, err := password.NewManager(r).ExportEncrypted(out, &password.ExportOptions{KDF: st.KDF()}, pw)
	if err != nil {
		return "", uiLocked(err)
	}
	if err := out.Finish(); err != nil {
		return "", fmt.Errorf("write the export to %s: %w", tildePath(dest), err)
	}
	return fmt.Sprintf("Exported %s to %s.", entryCount(n), tildePath(dest)), nil
}
