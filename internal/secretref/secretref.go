// Package secretref reads sesh references, sesh://<id>[#field], which name
// a value in the vault for sesh run and sesh inject to put in its place.
package secretref

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/bashhack/sesh/internal/password"
	"github.com/bashhack/sesh/internal/secure"
	"github.com/bashhack/sesh/internal/vault"
)

// Prefix starts every reference.
const Prefix = "sesh://"

// Ref names a value: an entry's secret, or with Field, one of its custom
// fields, its URL ("url"), or its notes ("notes"). A TOTP entry's secret
// is its current code.
type Ref struct {
	Field string
	Key   vault.Key
}

// String is the reference as Parse reads it.
func (r Ref) String() string {
	if r.Field == "" {
		return Prefix + r.Key.String()
	}
	return Prefix + r.Key.String() + "#" + r.Field
}

// Parse reads a reference: sesh://, an entry ID as --list shows it, and
// optionally # and a field name.
func Parse(s string) (Ref, error) {
	rest, ok := strings.CutPrefix(s, Prefix)
	if !ok {
		return Ref{}, fmt.Errorf("%q isn't a sesh reference: it starts %s, then an entry ID such as api_key/openai", s, Prefix)
	}
	id, field, hasField := strings.Cut(rest, "#")
	k, err := vault.ParseKey(id)
	if err != nil {
		return Ref{}, fmt.Errorf("%s: %w", s, err)
	}
	r := Ref{Key: k, Field: field}
	if hasField {
		if field == "" {
			return Ref{}, fmt.Errorf("%s names no field after #", s)
		}
		if !slices.Contains(vault.ReservedFieldNames, strings.ToLower(field)) {
			if err := vault.CheckFieldName(field); err != nil {
				return Ref{}, fmt.Errorf("%s: %w", s, err)
			}
		}
	}
	return r, nil
}

// Value is what a reference resolves to; Secret says whether it's secret
// (a secret, notes, a secret field, or a TOTP code) or not (a URL or a
// plain field). The caller zeroes Value.
type Value struct {
	Value  []byte
	Secret bool
}

// Resolve reads r's value from store. reading says what for, for the
// audit log ("run", "inject").
func Resolve(store vault.Store, r Ref, reading string) (Value, error) {
	v, err := resolve(store, r, reading)
	if err != nil {
		return Value{}, fmt.Errorf("%s: %w", r, err)
	}
	return v, nil
}

func resolve(store vault.Store, r Ref, reading string) (Value, error) {
	k := r.Key
	e, err := store.Lookup(k)
	if err != nil {
		if errors.Is(err, vault.ErrNotFound) {
			if h := password.CaseHint(store, k); h != "" {
				err = fmt.Errorf("%w; %s", err, h)
			}
		}
		return Value{}, err
	}
	field := strings.ToLower(r.Field)
	if field == "" || field == "password" || field == "secret" {
		if k.Kind == vault.KindTOTP {
			code, err := password.NewManager(store).GenerateTOTPCode(k.Service, k.Username)
			return Value{Value: []byte(code), Secret: true}, err
		}
		secret, err := store.Get(k)
		return Value{Value: secret, Secret: true}, err
	}
	switch field {
	case "url":
		if e.URL == "" {
			return Value{}, fmt.Errorf("%s has no URL", k)
		}
		return Value{Value: []byte(e.URL)}, nil
	case "notes":
		if !e.HasNotes {
			return Value{}, fmt.Errorf("%s has no notes", k)
		}
		d, err := store.Details(k, "notes, to "+reading)
		if err != nil {
			return Value{}, err
		}
		defer d.Zero()
		return Value{Value: bytes.Clone(d.Notes), Secret: true}, nil
	}
	i := slices.IndexFunc(e.Fields, func(f vault.Field) bool { return strings.EqualFold(f.Name, r.Field) })
	if i < 0 {
		if len(e.Fields) == 0 {
			return Value{}, fmt.Errorf("%s has no field %q; it has no fields", k, r.Field)
		}
		names := make([]string, len(e.Fields))
		for j, f := range e.Fields {
			names[j] = f.Name
		}
		return Value{}, fmt.Errorf("%s has no field %q; its fields: %s", k, r.Field, strings.Join(names, ", "))
	}
	f := e.Fields[i]
	if !f.Secret {
		return Value{Value: f.Value}, nil
	}
	d, err := store.Details(k, "field "+f.Name+", to "+reading)
	if err != nil {
		return Value{}, err
	}
	defer d.Zero()
	sf, ok := d.Field(f.Name)
	if !ok {
		return Value{}, fmt.Errorf("%s has no field %q", k, f.Name)
	}
	return Value{Value: bytes.Clone(sf.Value), Secret: true}, nil
}

// Zero overwrites v's value.
func (v *Value) Zero() { secure.SecureZeroBytes(v.Value) }
