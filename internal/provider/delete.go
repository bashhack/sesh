package provider

import (
	"errors"
	"fmt"
	"strings"

	"github.com/bashhack/sesh/internal/vault"
)

// ConfirmDelete asks whether to delete the entries ids name, which all
// exist; false deletes nothing.
type ConfirmDelete func(ids []string) (bool, error)

// ErrDeleteCancelled is a delete the person declined.
var ErrDeleteCancelled = errors.New("delete cancelled; nothing was deleted")

// deleteProblems are the IDs a delete refused, so it deleted nothing.
type deleteProblems []error

func (d deleteProblems) Error() string {
	lines := make([]string, len(d))
	for i, err := range d {
		lines[i] = err.Error()
	}
	return "nothing was deleted:\n  " + strings.Join(lines, "\n  ")
}

func (d deleteProblems) Unwrap() []error { return d }

// DeleteEntries deletes the entries ids name from store, all or none, and
// returns how many it deleted. Every ID must parse, be one own accepts (nil
// accepts any), and name an entry; otherwise nothing is deleted, and the
// error names each bad ID, with hint's suggestion (it may return "") for a
// missing one. Unless force, confirm is asked first. An ID named twice is
// deleted once.
func DeleteEntries(store vault.Store, ids []string, own func(vault.Key) error, hint func(vault.Key) string, force bool, confirm ConfirmDelete) (int, error) {
	if len(ids) == 0 {
		return 0, errors.New("name at least one entry ID to delete")
	}
	var keys []vault.Key
	var names []string
	var problems deleteProblems
	seen := map[vault.Key]bool{}
	for _, id := range ids {
		k, err := vault.ParseKey(id)
		if err == nil && own != nil {
			err = own(k)
		}
		if err == nil {
			if _, lerr := store.Lookup(k); lerr != nil {
				err = lerr
				if errors.Is(lerr, vault.ErrNotFound) && hint != nil {
					if h := hint(k); h != "" {
						err = fmt.Errorf("%w; %s", lerr, h)
					}
				}
			}
		}
		if err != nil {
			problems = append(problems, err)
			continue
		}
		if !seen[k] {
			seen[k] = true
			keys = append(keys, k)
			names = append(names, k.String())
		}
	}
	switch {
	case len(problems) == 1 && len(ids) == 1:
		return 0, problems[0]
	case len(problems) > 0:
		return 0, problems
	}
	if !force {
		ok, err := confirm(names)
		if err != nil {
			return 0, err
		}
		if !ok {
			return 0, ErrDeleteCancelled
		}
	}
	if err := store.DeleteMany(keys); err != nil {
		return 0, err
	}
	return len(keys), nil
}
