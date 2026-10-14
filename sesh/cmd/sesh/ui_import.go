package main

import (
	"bytes"
	"errors"
	"strings"

	"github.com/bashhack/sesh/internal/secure"
	"github.com/bashhack/sesh/internal/tui"
)

// uiImport is an import in the app: its files read again each time it's
// planned, since planning changes the entries it's given.
type uiImport struct {
	u        *uiVault
	f        *found
	plan     *importPlan
	source   string
	files    []string
	password []byte
}

// StartImport reads files from source for an import, as sesh import does;
// password is an export's own (nil until one asks for it, with
// tui.NeedsPassword).
func (u *uiVault) StartImport(source string, files []string, password []byte) (tui.Importer, error) {
	paths := make([]string, 0, len(files))
	for _, f := range files {
		p, err := uiPath(f)
		if err != nil {
			return nil, err
		}
		paths = append(paths, p)
	}
	if len(paths) == 0 {
		return nil, errors.New("name the file to import")
	}
	im := &uiImport{u: u, source: source, files: paths, password: bytes.Clone(password)}
	if _, err := im.read(); err != nil {
		im.Close()
		return nil, err
	}
	return im, nil
}

// read reads the import's files afresh.
func (im *uiImport) read() (*found, error) {
	if im.f != nil {
		im.f.wipe()
	}
	f, err := readImport(im.source, im.files, strings.NewReader(""), true, func(what string) ([]byte, error) {
		if len(im.password) == 0 {
			return nil, tui.NeedsPassword(what)
		}
		return bytes.Clone(im.password), nil
	})
	if err != nil {
		return nil, uiLocked(err)
	}
	im.f = &f
	return im.f, nil
}

// Plan sorts the import's entries against the vault, onConflict saying
// what's done with those the vault has ("" for neither yet).
func (im *uiImport) Plan(onConflict string) (tui.ImportPlan, error) {
	f, err := im.read()
	if err != nil {
		return tui.ImportPlan{}, err
	}
	st, err := settings()
	if err != nil {
		return tui.ImportPlan{}, err
	}
	p, err := planImport(im.u.store, f, onConflict, st.HistoryKeep.Value)
	if err != nil {
		return tui.ImportPlan{}, uiLocked(err)
	}
	im.plan = p
	return tui.ImportPlan{Summary: strings.TrimSpace(p.summary()), Count: p.count(), Clashes: len(p.clashes)}, nil
}

// Apply writes the planned import, and says what it did.
func (im *uiImport) Apply() (string, error) {
	if im.plan == nil {
		return "", errors.New("nothing is planned")
	}
	said, err := im.plan.apply(im.u.store)
	if err := im.u.wrote(err); err != nil {
		return "", err
	}
	return strings.Join(strings.Fields(strings.ReplaceAll(said, "✅ ", "")), " "), nil
}

// Close wipes what the import read, and the password.
func (im *uiImport) Close() {
	if im.f != nil {
		im.f.wipe()
	}
	secure.SecureZeroBytes(im.password)
}
