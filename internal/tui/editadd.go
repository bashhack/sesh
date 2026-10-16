package tui

import (
	"bytes"
	"errors"
	"path/filepath"
	"slices"
	"strings"

	tea "charm.land/bubbletea/v2"

	"github.com/bashhack/sesh/internal/secure"
	"github.com/bashhack/sesh/internal/vault"
)

// savedMsg is an entry saved from a form, or why it wasn't.
type savedMsg struct {
	err   error
	what  string
	k, of vault.Key // the name it has, and the one it had (zero: added)
	epoch int
}

// The kinds an entry added can be, in the order the form offers them.
var addKinds = []vault.Kind{vault.KindPassword, vault.KindAPIKey, vault.KindNote, vault.KindTOTP, vault.KindFile}

// secretChoices are what can be done to a secret in a form.
const (
	secretKeep     = "keep"
	secretType     = "type a new one"
	secretGenerate = "generate one"
	secretPaste    = "paste a new key"
)

// How a TOTP entry added gets its key.
const (
	totpPaste = "paste it, or its otpauth:// link"
	totpScan  = "scan a QR code on screen"
	totpImage = "read a QR code from an image file"
)

// openEdit opens the form that edits e.
func (m *Model) openEdit(e *vault.Entry) tea.Cmd { return m.openEditWith(e, "") }

// openEditWith opens the form that edits e, its secret's choice at choice
// ("" leaves it at keeping the secret).
func (m *Model) openEditWith(e *vault.Entry, choice string) tea.Cmd {
	notes, held := m.notes[e.Key]
	switch why := m.notesFailed[e.Key]; {
	case hasNotes(e) && !held && why != "":
		m.sayBad("Can't edit it here: its notes couldn't be read (" + why + ").")
		return nil
	case hasNotes(e) && !held:
		m.sayBad("Its notes are still being read; try again in a moment.")
		return nil
	}
	ek := *e
	cmd := m.openForm(&ek, string(notes))
	if m.form != nil && choice != "" {
		for _, in := range m.form.inputs {
			if in.kind == inputChoice && in.label == "secret" {
				in.choice = max(slices.Index(in.choices, choice), 0)
			}
		}
	}
	return cmd
}

// openAdd opens the form that adds an entry.
func (m *Model) openAdd() tea.Cmd { return m.openForm(nil, "") }

// openForm opens the form for e, or for a new entry when e is nil, with
// its notes (a secure note's text) as they are.
func (m *Model) openForm(e *vault.Entry, notes string) tea.Cmd {
	adding := e == nil
	if adding {
		e = &vault.Entry{}
	}
	kindIn := &input{kind: inputChoice, label: "kind", choices: []string{"password", "API key", "secure note", "TOTP", "file"}}
	if m.opts.ReadFile == nil {
		kindIn.choices = kindIn.choices[:4] // a file can't be read here
	}
	// An entry edited can become another of the first three kinds, keeping
	// its secret, as sesh edit --type does; a TOTP or file entry stays one.
	changesKind := !adding && e.Kind != vault.KindTOTP && e.Kind != vault.KindFile
	if changesKind {
		kindIn.choices = kindIn.choices[:3]
		kindIn.choice = max(slices.Index(addKinds, e.Kind), 0)
		kindIn.hint = "the secret stays as it is: a note's text becomes the password or key, and theirs the note's"
	}
	kind := func() vault.Kind {
		if adding || changesKind {
			return addKinds[kindIn.choice]
		}
		return e.Kind
	}
	// Into or out of a secure note, the notes input would be the note's
	// text, or the other way round: it's left out, the notes as they are.
	crossesNote := func() bool { return !adding && (kind() == vault.KindNote) != (e.Kind == vault.KindNote) }
	name := m.textInput("name", e.Service)
	user := m.textInput("username", e.Username)
	user.shown = func() bool { return kind() != vault.KindNote }
	user.named = func() string {
		if kind() == vault.KindTOTP {
			return "account"
		}
		return "username"
	}

	choices := []string{secretKeep, secretType, secretGenerate}
	if adding {
		choices = choices[1:]
	}
	secretChoice := &input{kind: inputChoice, label: "secret", choices: choices}
	secretChoice.shown = func() bool { k := kind(); return k == vault.KindPassword || k == vault.KindAPIKey }
	gen := m.generateInputs()
	gen.shownWhen(func() bool {
		return secretChoice.visible() && secretChoice.choices[secretChoice.choice] == secretGenerate
	})
	typed := &input{kind: inputSecret, label: "new secret", rated: true}
	typed.named = func() string { return "new " + secretWord(kind()) }
	typed.shown = func() bool { return secretChoice.visible() && secretChoice.choices[secretChoice.choice] == secretType }
	// The secret kept, unread until Ctrl-R asks to see it.
	current := &input{kind: inputSecret, readOnly: true}
	current.named = func() string { return "current " + secretWord(kind()) }
	current.shown = func() bool {
		return !adding && secretChoice.visible() && secretChoice.choices[secretChoice.choice] == secretKeep
	}
	if !adding {
		k, epoch := e.Key, m.epoch
		current.load = func() tea.Cmd {
			return m.read(func(v Vault, closed func() bool) tea.Msg {
				value, err := v.Secret(k, "in sesh ui, to reveal it")
				if closed() {
					secure.SecureZeroBytes(value)
					return nil
				}
				return fieldValueMsg{in: current, value: value, err: err, epoch: epoch}
			})
		}
	}
	// A QR code gives the key: on screen, or in an image file, where the
	// app can read them.
	from := []string{totpPaste}
	if m.opts.ScanQR != nil {
		from = append(from, totpScan)
	}
	if m.opts.ReadQRImage != nil {
		from = append(from, totpImage)
	}
	totpFrom := &input{kind: inputChoice, label: "TOTP key", choices: from,
		hint: "a QR code's issuer and account fill a name and username left empty"}
	if m.opts.ScanQR != nil {
		totpFrom.hint += "; scanning, you select the area of the screen with it once the form is saved"
	}
	totpFrom.shown = func() bool { return adding && kind() == vault.KindTOTP && len(from) > 1 }
	scanning := func() bool { return totpFrom.visible() && totpFrom.choices[totpFrom.choice] == totpScan }
	fromImage := func() bool { return totpFrom.visible() && totpFrom.choices[totpFrom.choice] == totpImage }
	imageFile := m.textInput("image file", "")
	imageFile.hint = "a screenshot or a photo of the QR code, PNG or JPEG: its full path, or from ~/"
	imageFile.shown = fromImage
	totpKey := &input{kind: inputSecret, label: "TOTP key, or otpauth:// link", hint: "a link brings its own code settings; a key alone gives 6-digit codes every 30s"}
	totpKey.shown = func() bool { return kind() == vault.KindTOTP && !scanning() && !fromImage() }
	if !adding {
		totpKey.label, totpKey.hint = "new TOTP key, or otpauth:// link", "leave it empty to keep the current key; a key alone gives 6-digit codes every 30s"
	}

	url := m.textInput("URL", e.URL)
	folder := m.textInput("folder", e.Folder)
	tags := m.textInput("tags", strings.Join(e.Tags, ", "))
	folder.hint = "a new name makes a new folder; / puts one inside another (work/aws)"
	tags.hint, tags.many = "separated by commas", true
	text := m.notesInput("notes", notes)
	text.shown = func() bool { return !crossesNote() }
	// The input may show the notes a little differently (a tab as spaces):
	// they're saved only when what it shows was changed.
	shownNotes := text.area.Value()
	text.named = func() string {
		if kind() == vault.KindNote {
			return "note"
		}
		return "notes"
	}
	fields := &input{kind: inputFields, label: "fields", of: e.Key}
	for _, f := range e.Fields {
		fields.rows = append(fields.rows, fieldRow{name: f.Name, orig: f.Name, secret: f.Secret, value: bytes.Clone(f.Value)})
	}

	// A file entry's file, read from the path typed once the form is saved.
	fileIn := m.textInput("file", "")
	fileIn.hint = "the file to keep, up to 1 MB: a full path, or from ~/; it names an entry given no name"
	if !adding {
		fileIn.label, fileIn.hint = "new file", "leave it empty to keep the file it has; a full path, or from ~/"
	}
	fileIn.shown = func() bool { return kind() == vault.KindFile && m.opts.ReadFile != nil }

	title := "Edit " + entryName(e)
	inputs := slices.Concat([]*input{name, user, secretChoice, current, typed}, gen.inputs(), []*input{totpFrom, imageFile, totpKey, fileIn, url, folder, tags, text, fields})
	switch {
	case adding:
		title = "Add an entry"
		inputs = append([]*input{kindIn}, inputs...)
	case changesKind:
		inputs = slices.Insert(inputs, 2, kindIn) // after the name and username
	}
	f := &form{title: title, inputs: inputs, row: -1}
	orig := *e
	f.submit = func() tea.Cmd {
		k := kind()
		c := &Change{To: vault.Key{Kind: k, Service: name.value(), Username: user.value()}}
		fromFile := ""
		if k == vault.KindFile {
			fromFile = fileIn.value()
			switch {
			case adding && fromFile == "":
				f.err = "Give the file to keep."
				return nil
			case adding && c.To.Service == "":
				// Named after the file, as sesh add file is: worked out
				// again at each save, so a path typed again names it.
				c.To.Service = filepath.Base(fromFile)
			}
		}
		if k == vault.KindNote && adding {
			// Edited, a note keeps the username it has, as sesh edit
			// --type does; added, it has none.
			c.To.Username = ""
		}
		if c.To.Service == "" && !scanning() && !fromImage() {
			f.err = "Give it a name."
			return nil
		}
		if !adding {
			c.Key = orig.Key
		}
		if u := url.value(); adding && u != "" || !adding && u != orig.URL {
			c.URL = &u
		}
		if fo := folder.value(); adding && fo != "" || !adding && fo != orig.Folder {
			c.Folder = &fo
		}
		var tagList []string
		for t := range strings.SplitSeq(tags.value(), ",") {
			if t = strings.TrimSpace(t); t != "" && !slices.Contains(tagList, t) {
				tagList = append(tagList, t)
			}
		}
		if adding && len(tagList) > 0 || !adding && !slices.Equal(tagList, orig.Tags) {
			c.Tags, c.TagsSet = tagList, true
		}

		// The secret: typed, generated, a TOTP key, or a secure note's text.
		var generate *generating
		noteText := []byte(text.area.Value())
		if crossesNote() {
			if string(noteText) != shownNotes {
				f.err = "Changing the kind keeps the text as it was: undo your change to it, or save that first, then change the kind."
				return nil
			}
			if k == vault.KindNote && hasNotes(&orig) {
				f.err = "A secure note can't have notes: its text is its secret. Remove the notes first, then make it a note."
				return nil
			}
		}
		switch {
		case k == vault.KindNote:
			if !adding && string(noteText) == shownNotes {
				break
			}
			if len(bytes.TrimSpace(noteText)) == 0 {
				f.err = "Write the note's text."
				return nil
			}
			c.Secret = noteText
		case k == vault.KindTOTP && scanning():
			// Read once the rest is checked, below.
		case k == vault.KindFile:
			// Its content is read from fromFile as it saves.
		case k == vault.KindTOTP && fromImage():
			if imageFile.value() == "" {
				f.err = "Give the image file with the QR code."
				return nil
			}
		case k == vault.KindTOTP:
			if len(totpKey.secret) > 0 {
				c.Secret = bytes.Clone(totpKey.secret)
			} else if adding {
				f.err = "Paste the TOTP key, or its otpauth:// link."
				return nil
			}
		case secretChoice.choices[secretChoice.choice] == secretType:
			if len(typed.secret) == 0 {
				f.err = "Type the new " + secretWord(k) + ", or choose another option."
				return nil
			}
			c.Secret = bytes.Clone(typed.secret)
		case secretChoice.choices[secretChoice.choice] == secretGenerate:
			g, bad := gen.read()
			if bad != "" {
				f.err = bad
				return nil
			}
			generate = &g
		}
		if k != vault.KindNote {
			if adding && len(noteText) > 0 || !adding && string(noteText) != shownNotes {
				c.Notes, c.SetNotes = noteText, true
				if !adding {
					c.NotesBase = []byte(notes)
				}
			}
		}

		// The fields: those taken out, renamed, changed, or added.
		// A field renamed, or made plain, is taken out before it's set
		// again (the store removes first).
		wasSecret := func(name string) bool {
			return slices.ContainsFunc(orig.Fields, func(of vault.Field) bool { return of.Name == name && of.Secret })
		}
		for _, r := range fields.rows {
			if r.orig != "" && (r.orig != r.name || r.changed && !r.secret && wasSecret(r.orig)) {
				c.RemoveFields = append(c.RemoveFields, r.orig)
			}
			if r.changed {
				c.SetFields = append(c.SetFields, vault.Field{Name: r.name, Value: bytes.Clone(r.value), Secret: r.secret})
			}
		}
		for _, of := range orig.Fields {
			if !slices.ContainsFunc(fields.rows, func(r fieldRow) bool { return r.orig == of.Name }) {
				c.RemoveFields = append(c.RemoveFields, of.Name)
			}
		}
		if scanning() {
			// What the code names goes into the form, so a save refused
			// (a name taken) shows which.
			fill := func(service, username string) {
				name.text.SetValue(service)
				user.text.SetValue(username)
			}
			return m.scanThenSave(f, c, fill)
		}
		if fromImage() {
			fill := func(service, username string) {
				name.text.SetValue(service)
				user.text.SetValue(username)
			}
			return m.readImageThenSave(f, c, fill, imageFile.value())
		}
		return m.save(f, c, generate, fromFile)
	}
	folder.offers, tags.offers = m.folderNames(), m.tagNames()
	f.focusInput(0)
	m.form = f
	return nil
}

// save saves c, generating its password first when generate says how,
// which is then copied, since nobody has seen it; or, for a file entry,
// reading its file from the path typed, fromFile, when one is.
func (m *Model) save(f *form, c *Change, generate *generating, fromFile string) tea.Cmd {
	f.saving, f.err = true, ""
	opts, epoch, of := m.opts, m.epoch, c.Key
	read := m.read(func(v Vault, _ func() bool) tea.Msg {
		defer c.Wipe()
		if fromFile != "" {
			if opts.ReadFile == nil {
				return savedMsg{err: errors.New("sesh ui can't read files here"), epoch: epoch}
			}
			content, fileName, err := opts.ReadFile(fromFile)
			if err != nil {
				return savedMsg{err: err, epoch: epoch}
			}
			c.Secret, c.FileName = content, &fileName
		}
		if generate != nil {
			pw, err := generate.make(&opts)
			if err != nil {
				return savedMsg{err: err, epoch: epoch}
			}
			c.Secret = pw
		}
		k, err := v.Save(c)
		if err != nil {
			return savedMsg{err: err, epoch: epoch}
		}
		what := "Saved " + kindName(k)
		if of == (vault.Key{}) {
			what = "Added " + kindName(k)
		}
		if generate != nil {
			if err := opts.Copy(string(c.Secret)); err != nil {
				what += "; the new " + secretWord(k.Kind) + " couldn't be copied: " + err.Error()
			} else {
				what = copied("the new "+secretWord(k.Kind)+" for "+keyName(k), opts.ClearAfter)
			}
		}
		return savedMsg{k: k, of: of, what: what, epoch: epoch}
	})
	return func() tea.Msg {
		msg := read()
		if msg == nil {
			// The app locked before the save began: nothing was saved.
			c.Wipe()
		}
		return msg
	}
}

// scannedMsg is a QR code read for the add form, or why it wasn't.
type scannedMsg struct {
	err   error
	c     *Change
	fill  func(service, username string) // puts the names used in the form
	qr    ScannedQR
	epoch int
}

// scanThenSave reads the TOTP key for c from a QR code on screen, then
// saves it as save does. Ctrl-C meanwhile quits once the screen capture
// ends, which Esc on its crosshair does, saving nothing.
func (m *Model) scanThenSave(f *form, c *Change, fill func(service, username string)) tea.Cmd {
	f.saving, f.err, f.working = true, "", "Select the area of the screen with the QR code (Esc there cancels)…"
	m.scanning = true
	f.quitting = "Quitting once the screen capture ends: Esc on its crosshair cancels it."
	scan, epoch := m.opts.ScanQR, m.epoch
	return func() tea.Msg {
		qr, err := scan()
		return scannedMsg{qr: qr, err: err, c: c, fill: fill, epoch: epoch}
	}
}

// readImageThenSave reads the TOTP key for c from a QR code in the image
// file at path, then saves it as save does.
func (m *Model) readImageThenSave(f *form, c *Change, fill func(service, username string), path string) tea.Cmd {
	f.saving, f.err, f.working = true, "", "Reading the QR code…"
	read, epoch := m.opts.ReadQRImage, m.epoch
	return func() tea.Msg {
		qr, err := read(path)
		return scannedMsg{qr: qr, err: err, c: c, fill: fill, epoch: epoch}
	}
}

// scanned saves the entry the add form describes with the key a QR code
// gave, its issuer and account naming it where the form left that empty;
// or says why the code couldn't be used.
func (m *Model) scanned(msg *scannedMsg) tea.Cmd {
	c := msg.c
	m.scanning = false
	switch {
	case m.quitAfter:
		secure.SecureZeroBytes(msg.qr.Link)
		c.Wipe()
		return tea.Quit
	case msg.epoch != m.epoch || m.v == nil || m.form == nil:
		secure.SecureZeroBytes(msg.qr.Link)
		c.Wipe()
		return nil
	}
	f := m.form
	f.saving, f.working, f.quitting = false, "", ""
	switch {
	case msg.err != nil:
		f.err = "No QR code read: " + msg.err.Error()
		secure.SecureZeroBytes(msg.qr.Link)
		c.Wipe()
		return nil
	case c.To.Service == "" && msg.qr.Issuer == "":
		f.err = "The QR code doesn't name its issuer: give the entry a name, and save it again."
		secure.SecureZeroBytes(msg.qr.Link)
		c.Wipe()
		return nil
	}
	if c.To.Service == "" {
		c.To.Service = msg.qr.Issuer
	}
	if c.To.Username == "" {
		c.To.Username = msg.qr.Account
	}
	if msg.fill != nil {
		msg.fill(c.To.Service, c.To.Username)
	}
	c.Secret = msg.qr.Link
	return m.save(f, c, nil, "")
}

// saved closes the form for an entry saved, or says why it wasn't.
func (m *Model) saved(msg *savedMsg) tea.Cmd {
	if msg.epoch != m.epoch || m.v == nil || m.form == nil {
		return nil
	}
	m.form.saving = false
	switch {
	case errors.Is(msg.err, ErrLocked):
		m.form.wipe()
		m.form = nil
		return m.lock(lockedReason(msg.err))
	case errors.Is(msg.err, ErrNameTaken):
		m.form.err = "Another entry has that name; choose another."
		return nil
	case msg.err != nil:
		m.form.err = "Not saved: " + msg.err.Error()
		return nil
	}
	m.form.wipe()
	m.form = nil
	// What the app held of the entry is read again, from the vault.
	m.forget(msg.k)
	m.forget(msg.of)
	m.selKey = msg.k
	m.say(msg.what)
	return m.reread()
}

// editedNotes puts what the editor saved into the notes input.
func (m *Model) editedNotes(msg *editorMsg) tea.Cmd {
	defer secure.SecureZeroBytes(msg.notes)
	// The time in the editor was use: the idle lock starts again from now.
	m.lastKey, m.inEditor = m.opts.Now(), false
	f := m.form
	if f == nil || f.inputs[f.focus].kind != inputNotes {
		return nil
	}
	if msg.err != nil {
		f.err = msg.err.Error()
		return nil
	}
	f.inputs[f.focus].area.SetValue(string(msg.notes))
	return nil
}
