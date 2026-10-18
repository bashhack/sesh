package vaultsync

import (
	"slices"
	"strings"
	"testing"

	"github.com/bashhack/sesh/internal/database"
	"github.com/bashhack/sesh/internal/vault"
)

// orders are every order of n computers (as computers names them), by
// index, each named by its computers.
func orders(n int) map[string][]int {
	names := []string{"laptop", "desktop", "third", "fourth"}
	out := map[string][]int{}
	var walk func(done, left []int)
	walk = func(done, left []int) {
		if len(left) == 0 {
			var ns []string
			for _, i := range done {
				ns = append(ns, names[i])
			}
			out[strings.Join(ns, ",")] = done
			return
		}
		for j, i := range left {
			walk(append(slices.Clone(done), i), slices.Concat(left[:j], left[j+1:]))
		}
	}
	all := make([]int, n)
	for i := range all {
		all[i] = i
	}
	walk(nil, all)
	return out
}

// inOrder is cs in order (indices).
func inOrder(cs []*computer, order []int) []*computer {
	var out []*computer
	for _, i := range order {
		out = append(out, cs[i])
	}
	return out
}

// forgetOld forgets k's newest earlier secret on c, which must be pw-old.
func forgetOld(t *testing.T, c *computer, k vault.Key) {
	t.Helper()
	const want = "pw-old"
	rec, _, err := c.store.SyncRecord(liveUID(t, c, k), "x")
	if err != nil {
		t.Fatal(err)
	}
	if len(rec.History) == 0 || string(rec.History[0].Secret) != want {
		t.Fatalf("%s: newest earlier secret of %s isn't %s: %q", c.name, k, want, secrets(rec.History))
	}
	if err := c.store.ForgetVersions(k, 2); err != nil {
		t.Fatal(err)
	}
}

// noneHas fails t if any of cs has secret, as its secret or an earlier one.
func noneHas(t *testing.T, cs []*computer, secret string) {
	t.Helper()
	for _, c := range cs {
		if all := allSecrets(t, c); slices.Contains(all, secret) {
			t.Errorf("%s: %s, forgotten on purpose, is back (all %q)", c.name, secret, all)
		}
	}
}

// allHave fails t unless each of cs has secret, as its secret or an earlier one.
func allHave(t *testing.T, cs []*computer, secret string) {
	t.Helper()
	for _, c := range cs {
		if all := allSecrets(t, c); !slices.Contains(all, secret) {
			t.Errorf("%s: %s, used again after it was forgotten, is gone (all %q)", c.name, secret, all)
		}
	}
}

// A password forgotten on one computer stays forgotten though two others,
// not synced since, each replace it afterwards: in any order.
func TestSync_ForgetThenTwoReplace(t *testing.T) {
	t.Parallel()
	for name, order := range orders(3) {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			cs, _, f := computers(t, 3)
			laptop, desktop, third := cs[0], cs[1], cs[2]
			gh := laptop.put("github", "pw-old")
			settleN(t, f, 6, cs...)
			laptop.put("github", "pw-laptop")
			forgetOld(t, laptop, gh)
			desktop.put("github", "pw-desktop")
			third.put("github", "pw-third")
			settleN(t, f, 8, inOrder(cs, order)...)
			noneHas(t, cs, "pw-old")
		})
	}
}

// A password forgotten, then typed again and replaced before any sync, is
// kept everywhere: whichever syncs first.
func TestSync_ForgottenReusedUnsynced(t *testing.T) {
	t.Parallel()
	for name, order := range orders(2) {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			cs, _, f := computers(t, 2)
			laptop := cs[0]
			gh := laptop.put("github", "pw-old")
			settleN(t, f, 6, cs...)
			laptop.put("github", "pw-laptop")
			forgetOld(t, laptop, gh)
			laptop.put("github", "pw-old")
			laptop.put("github", "pw-new")
			settleN(t, f, 6, inOrder(cs, order)...)
			allHave(t, cs, "pw-old")
		})
	}
}

// A password forgotten on one computer, then typed again and replaced on
// another that took the forgetting, is kept everywhere: in any order.
func TestSync_ForgottenReusedElsewhere(t *testing.T) {
	t.Parallel()
	for name, order := range orders(3) {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			cs, _, f := computers(t, 3)
			laptop, desktop, third := cs[0], cs[1], cs[2]
			gh := laptop.put("github", "pw-old")
			settleN(t, f, 6, cs...)
			laptop.put("github", "pw-laptop")
			forgetOld(t, laptop, gh)
			laptop.sync(f)
			desktop.sync(f)
			desktop.put("github", "pw-old")
			desktop.put("github", "pw-desktop")
			// The third computer, not synced since pw-old was forgotten,
			// changes something else.
			if _, err := third.store.Edit(gh, database.EntryEdit{Tags: &[]string{"work"}}); err != nil {
				t.Fatal(err)
			}
			settleN(t, f, 8, inOrder(cs, order)...)
			allHave(t, cs, "pw-old")
		})
	}
}

// A password forgotten on one computer, then typed again and replaced on
// another that also has its use before, is kept: in any order, as a third
// computer's change has the second merge both uses before the forgetting
// reaches it.
func TestSync_ForgottenReusedBeforeTaken(t *testing.T) {
	t.Parallel()
	for name, order := range orders(3) {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			cs, _, f := computers(t, 3)
			laptop, desktop, third := cs[0], cs[1], cs[2]
			gh := laptop.put("github", "pw-old")
			settleN(t, f, 6, cs...)
			desktop.put("github", "pw-desktop")
			settleN(t, f, 6, cs...)
			forgetOld(t, laptop, gh)
			// The desktop, not synced since, has pw-old's first use in its
			// history, and uses it again.
			desktop.put("github", "pw-old")
			desktop.put("github", "pw-new")
			if _, err := third.store.Edit(gh, database.EntryEdit{Tags: &[]string{"work"}}); err != nil {
				t.Fatal(err)
			}
			settleN(t, f, 8, inOrder(cs, order)...)
			allHave(t, cs, "pw-old")
		})
	}
}

// A password forgotten on one computer stays forgotten though the other
// replaced it afterwards with what it last synced at damaged.
func TestSync_ForgetThenReplaceDamagedBase(t *testing.T) {
	t.Parallel()
	for name, order := range orders(2) {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			cs, paths, f := computers(t, 2)
			laptop, desktop := cs[0], cs[1]
			gh := laptop.put("github", "pw-old")
			settleN(t, f, 6, cs...)
			laptop.put("github", "pw-laptop")
			forgetOld(t, laptop, gh)
			desktop.put("github", "pw-desktop")
			rawExec(t, paths[1], `UPDATE sync_state SET base = x'00'`)
			for range 4 {
				for _, c := range inOrder(cs, order) {
					syncLoose(c, f)
				}
			}
			noneHas(t, cs, "pw-old")
		})
	}
}

// A password set on a computer whose clock is ahead, forgotten on another,
// stays forgotten though the first replaces it afterwards: in any order.
func TestSync_ForgetSetClockAhead(t *testing.T) {
	t.Parallel()
	for name, order := range orders(2) {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			cs, paths, f := computers(t, 2)
			laptop, desktop := cs[0], cs[1]
			gh := desktop.put("github", "pw-old")
			// The desktop's clock is 10 minutes ahead.
			rawExec(t, paths[1], `UPDATE entries SET updated_at = strftime('%Y-%m-%d %H:%M:%f', 'now', '+10 minutes')`)
			settleN(t, f, 6, cs...)
			laptop.put("github", "pw-laptop")
			forgetOld(t, laptop, gh)
			desktop.put("github", "pw-desktop")
			rawExec(t, paths[1], `UPDATE history SET replaced_at = strftime('%Y-%m-%d %H:%M:%f', 'now', '+10 minutes')`)
			settleN(t, f, 6, inOrder(cs, order)...)
			noneHas(t, cs, "pw-old")
		})
	}
}
