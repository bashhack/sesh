package importer

import (
	"fmt"
	"strings"

	"github.com/bashhack/sesh/internal/secure"
	"github.com/bashhack/sesh/internal/vault"
)

// Place gives an item's entries their keys: as they are, or with " (2)",
// " (3)" ... added to the service name of all of them together when
// another item's entry has one already. It checks them again after.
func Place(entries []*Entry, taken map[vault.Key]bool) {
	var live []*Entry
	for _, e := range entries {
		if e.Skip == "" {
			live = append(live, e)
		}
	}
	for n := 1; ; n++ {
		keys := make([]vault.Key, len(live))
		free := true
		for i, e := range live {
			keys[i] = numbered(e.Key, n)
			free = free && !taken[keys[i]]
		}
		if !free {
			continue
		}
		for i, e := range live {
			if n > 1 {
				e.Changes = append(e.Changes, fmt.Sprintf("named %q in sesh: an entry before it has the name", keys[i].Service))
			}
			e.Key = keys[i]
			taken[keys[i]] = true
			Checked(e)
		}
		return
	}
}

// numbered is k with " (n)" added to its service name, cut to fit, for n
// above 1.
func numbered(k vault.Key, n int) vault.Key {
	if n == 1 {
		return k
	}
	suffix := fmt.Sprintf(" (%d)", n)
	r := []rune(k.Service)
	if limit := vault.MaxNameLength - len([]rune(suffix)); len(r) > limit {
		r = r[:limit]
	}
	k.Service = strings.TrimSpace(string(r)) + suffix
	return k
}

// NoteEntry makes base a secure note holding note, with fs's fields.
func NoteEntry(base *Entry, service, note string, fs *FieldSet) *Entry {
	base.Key = vault.Key{Kind: vault.KindNote, Service: service}
	base.Secret = []byte(note)
	base.Details = vault.Details{Fields: fs.Fields}
	base.Changes = append(base.Changes, fs.Changes...)
	return Checked(base)
}

// Checked marks e skipped when its name, folder, tags or details break
// sesh's rules, and returns it. A detail sesh can't hold is left out
// first (see fitDetails), so it doesn't cost the entry.
func Checked(e *Entry) *Entry {
	if e.Skip != "" {
		return e
	}
	fitDetails(e)
	err := e.Key.Validate()
	if err == nil {
		err = vault.CheckFolder(e.Folder)
	}
	for _, t := range e.Tags {
		if err == nil {
			err = vault.CheckTag(t)
		}
	}
	if err == nil {
		err = e.Details.Check(e.Key.Kind)
	}
	if err != nil {
		e.Skip = err.Error()
	}
	return e
}

// fitDetails leaves out of e's details each part sesh can't hold, saying
// why: notes or a URL with a character it refuses, or a field's value. A
// plain field that only a secret one can hold is made secret instead.
func fitDetails(e *Entry) {
	d := &e.Details
	if len(d.Notes) > 0 {
		if err := (&vault.Details{Notes: d.Notes}).Check(vault.KindPassword); err != nil {
			secure.SecureZeroBytes(d.Notes)
			d.Notes = nil
			e.Changes = append(e.Changes, "notes not kept: "+err.Error())
		}
	}
	if d.URL != "" {
		if err := (&vault.Details{URL: d.URL}).Check(e.Key.Kind); err != nil {
			d.URL = ""
			e.Changes = append(e.Changes, "URL not kept: "+err.Error())
		}
	}
	kept := d.Fields[:0]
	for _, f := range d.Fields {
		err := (&vault.Details{Fields: []vault.Field{f}}).Check(e.Key.Kind)
		if err != nil && !f.Secret {
			f.Secret = true
			if err = (&vault.Details{Fields: []vault.Field{f}}).Check(e.Key.Kind); err == nil {
				e.Changes = append(e.Changes, fmt.Sprintf("field %q is secret in sesh: a plain field can't hold one of its characters", f.Name))
			}
		}
		if err != nil {
			e.Changes = append(e.Changes, fmt.Sprintf("field %q not kept: %s", f.Name, err))
			secure.SecureZeroBytes(f.Value)
			continue
		}
		kept = append(kept, f)
	}
	d.Fields = kept
}

// FieldSet gathers an entry's fields as sesh holds them: names fitted and
// unique (ignoring case), at most vault.MaxFields, saying what changed.
type FieldSet struct {
	used    map[string]bool
	Fields  []vault.Field
	Changes []string
	dropped int
}

// Add adds a field sesh names, unless its value is empty.
func (s *FieldSet) Add(name, value string, secret bool) {
	if value == "" {
		return
	}
	s.put(FitFieldName(name), value, secret, "")
}

// Custom adds a field named by the source, from, made secret when secret
// is, or when its value has a line break or tab, which only a secret
// field can hold. An empty value is left out, and said.
func (s *FieldSet) Custom(from, value string, secret bool) {
	if value == "" {
		s.Changes = append(s.Changes, fmt.Sprintf("field %q not kept: it has no value", from))
		return
	}
	if !secret && strings.ContainsAny(value, "\n\r\t") {
		secret = true
		s.Changes = append(s.Changes, fmt.Sprintf("field %q is secret in sesh: it has a line break or tab", from))
	}
	s.put(FitFieldName(from), value, secret, from)
}

// put adds a field named name, made unique; from is the source's name for
// it, said when it changed ("" for a field sesh names).
func (s *FieldSet) put(name, value string, secret bool, from string) {
	if s.used == nil {
		s.used = map[string]bool{}
	}
	if len(s.Fields) == vault.MaxFields {
		s.dropped++
		if s.dropped == 1 {
			s.Changes = append(s.Changes, "") // the count goes here
		}
		for i := len(s.Changes) - 1; i >= 0; i-- {
			if s.Changes[i] == "" || strings.HasSuffix(s.Changes[i], fmt.Sprintf("sesh holds %d", vault.MaxFields)) {
				s.Changes[i] = fmt.Sprintf("%d fields not kept: sesh holds %d", s.dropped, vault.MaxFields)
				break
			}
		}
		return
	}
	base := name
	for n := 2; s.used[strings.ToLower(name)]; n++ {
		name = fmt.Sprintf("%s-%d", base, n)
	}
	s.used[strings.ToLower(name)] = true
	if from != "" && name != from {
		s.Changes = append(s.Changes, fmt.Sprintf("field %q is %q in sesh", from, name))
	}
	s.Fields = append(s.Fields, vault.Field{Name: name, Value: []byte(value), Secret: secret})
}
