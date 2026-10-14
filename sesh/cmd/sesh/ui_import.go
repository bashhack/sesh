package main

import (
	"bytes"
	"errors"
	"strings"
	"sync"

	"github.com/bashhack/sesh/internal/secure"
	"github.com/bashhack/sesh/internal/tui"
)

// uiImport is an import in the app: its files read again each time it's
// planned, since planning changes the entries it's given. Close waits for
// a plan or an apply under way, so what they use isn't wiped under them.
type uiImport struct {
	u        *uiVault
	f        *found
	plan     *importPlan
	source   string
	files    []string
	password []byte
	mu       sync.Mutex
	closed   bool
}

// errImportClosed is an import let go: nothing more is read or written.
var errImportClosed = errors.New("the import was let go")

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
	f, err := im.read()
	if err != nil {
		im.Close()
		return nil, err
	}
	im.f = f
	return im, nil
}

// read reads the import's files afresh, into a found of its own.
func (im *uiImport) read() (*found, error) {
	f, err := readImport(im.source, im.files, strings.NewReader(""), true, func(what string) ([]byte, error) {
		if len(im.password) == 0 {
			return nil, tui.NeedsPassword(what)
		}
		return bytes.Clone(im.password), nil
	})
	if err != nil {
		return nil, uiLocked(err)
	}
	return &f, nil
}

// Plan sorts the import's entries against the vault, onConflict saying
// what's done with those the vault has ("" for neither yet). A plan that
// fails leaves none: there's nothing to apply until one succeeds.
func (im *uiImport) Plan(onConflict string) (tui.ImportPlan, error) {
	im.mu.Lock()
	defer im.mu.Unlock()
	if im.closed {
		return tui.ImportPlan{}, errImportClosed
	}
	im.plan = nil
	if im.f != nil {
		im.f.wipe()
		im.f = nil
	}
	f, err := im.read()
	if err != nil {
		return tui.ImportPlan{}, err
	}
	im.f = f
	st, err := settings()
	if err != nil {
		return tui.ImportPlan{}, err
	}
	p, err := planImport(im.u.store, f, onConflict, st.HistoryKeep.Value)
	if err != nil {
		return tui.ImportPlan{}, uiLocked(err)
	}
	im.plan = p
	return tui.ImportPlan{Summary: strings.TrimSpace(p.summary()), Count: p.count(), Clashes: len(p.clashes), After: f.after}, nil
}

// Apply writes the planned import, and says what it did.
func (im *uiImport) Apply() (string, error) {
	im.mu.Lock()
	defer im.mu.Unlock()
	if im.closed {
		return "", errImportClosed
	}
	if im.plan == nil {
		return "", errors.New("nothing is planned")
	}
	said, err := im.plan.apply(im.u.store)
	// What was written is the app's own, whether or not all of it was.
	if werr := im.u.wrote(nil); err == nil {
		err = werr
	}
	if err = uiLocked(err); errors.Is(err, tui.ErrLocked) {
		return "", err
	}
	if err != nil {
		// sesh import's advice is for the command line; the app's s and o
		// do the same.
		msg := strings.NewReplacer(
			"run this again with --on-conflict skip", "import again, leaving those you have",
			"run this again with --on-conflict overwrite", "import again, replacing those you have",
		).Replace(err.Error())
		return "", errors.New(msg)
	}
	return strings.ReplaceAll(strings.TrimSpace(strings.ReplaceAll(said, "✅ ", "")), "\n", " "), nil
}

// Close wipes what the import read, and the password, once any plan or
// apply under way has finished.
func (im *uiImport) Close() {
	im.mu.Lock()
	defer im.mu.Unlock()
	im.closed = true
	im.plan = nil
	if im.f != nil {
		im.f.wipe()
		im.f = nil
	}
	secure.SecureZeroBytes(im.password)
}
