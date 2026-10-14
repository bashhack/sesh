package tui

import (
	"bytes"
	"errors"
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

// filingMsg is the folders and tags there are, for the inputs that offer
// them.
type filingMsg struct {
	folder, tags      *input
	folders, tagNames []string
	epoch             int
}

// The kinds an entry added can be, in the order the form offers them.
var addKinds = []vault.Kind{vault.KindPassword, vault.KindAPIKey, vault.KindNote, vault.KindTOTP}

// secretChoices are what can be done to a secret in a form.
const (
	secretKeep     = "keep"
	secretType     = "type a new one"
	secretGenerate = "generate one"
	secretPaste    = "paste a new key"
)

// openEdit opens the form that edits e.
func (m *Model) openEdit(e *vault.Entry) tea.Cmd {
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
	return m.openForm(&ek, string(notes))
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
	kindIn := &input{kind: inputChoice, label: "kind", choices: []string{"password", "API key", "secure note", "TOTP"}}
	kind := func() vault.Kind {
		if adding {
			return addKinds[kindIn.choice]
		}
		return e.Kind
	}
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
	typed := &input{kind: inputSecret, label: "new secret", rated: true}
	typed.named = func() string { return "new " + secretWord(kind()) }
	typed.shown = func() bool { return secretChoice.visible() && secretChoice.choices[secretChoice.choice] == secretType }
	totpKey := &input{kind: inputSecret, label: "TOTP key, or otpauth:// link", hint: "a link brings its own code settings; a key alone gives 6-digit codes every 30s"}
	totpKey.shown = func() bool { return kind() == vault.KindTOTP }
	if !adding {
		totpKey.label, totpKey.hint = "new TOTP key, or otpauth:// link", "leave it empty to keep the current key; a key alone gives 6-digit codes every 30s"
	}

	url := m.textInput("URL", e.URL)
	folder := m.textInput("folder", e.Folder)
	tags := m.textInput("tags", strings.Join(e.Tags, ", "))
	folder.hint = "a new name makes a new folder; / puts one inside another (work/aws)"
	tags.hint, tags.many = "separated by commas", true
	text := m.notesInput("notes", notes)
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

	title := "Edit " + entryName(e)
	inputs := []*input{name, user, secretChoice, typed, totpKey, url, folder, tags, text, fields}
	if adding {
		title = "Add an entry"
		inputs = append([]*input{kindIn}, inputs...)
	}
	f := &form{title: title, inputs: inputs, row: -1}
	orig := *e
	f.submit = func() tea.Cmd {
		k := kind()
		c := &Change{To: vault.Key{Kind: k, Service: name.value(), Username: user.value()}}
		if k == vault.KindNote {
			c.To.Username = ""
		}
		if c.To.Service == "" {
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
		generate := false
		noteText := []byte(text.area.Value())
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
			generate = true
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
		return m.save(f, c, generate)
	}
	f.focusInput(0)
	m.form = f
	epoch := m.epoch
	return m.read(func(v Vault, _ func() bool) tea.Msg {
		// Without them the form still works: there's only nothing offered.
		folders, tagNames, _ := v.Filing() //nolint:errcheck // see above
		return filingMsg{folder: folder, tags: tags, folders: folders, tagNames: tagNames, epoch: epoch}
	})
}

// save saves c, generating its password first when asked to, which is
// then copied, since nobody has seen it.
func (m *Model) save(f *form, c *Change, generate bool) tea.Cmd {
	f.saving, f.err = true, ""
	opts, epoch, of := m.opts, m.epoch, c.Key
	read := m.read(func(v Vault, _ func() bool) tea.Msg {
		defer c.Wipe()
		if generate {
			if opts.Generate == nil {
				return savedMsg{err: errors.New("sesh ui can't generate a password here"), epoch: epoch}
			}
			pw, err := opts.Generate()
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
		if generate {
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
	return m.search()
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
