package vaultsync

import (
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

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

// oldGone fails t if any of cs has pw-old, as its secret or an earlier one.
func oldGone(t *testing.T, cs []*computer) {
	t.Helper()
	const secret = "pw-old"
	for _, c := range cs {
		if all := allSecrets(t, c); slices.Contains(all, secret) {
			t.Errorf("%s: %s, forgotten on purpose, is back (all %q)", c.name, secret, all)
		}
	}
}

// oldKept fails t unless each of cs has pw-old, as its secret or an
// earlier one.
func oldKept(t *testing.T, cs []*computer) {
	t.Helper()
	const secret = "pw-old"
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
			oldGone(t, cs)
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
			oldKept(t, cs)
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
			if _, err := third.store.Edit(gh, &database.EntryEdit{Tags: &[]string{"work"}}); err != nil {
				t.Fatal(err)
			}
			settleN(t, f, 8, inOrder(cs, order)...)
			oldKept(t, cs)
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
			if _, err := third.store.Edit(gh, &database.EntryEdit{Tags: &[]string{"work"}}); err != nil {
				t.Fatal(err)
			}
			settleN(t, f, 8, inOrder(cs, order)...)
			oldKept(t, cs)
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
			oldGone(t, cs)
		})
	}
}

// A password forgotten on one computer, brought back by restoring a backup
// another took before it heard, is the password until replaced on either,
// then forgotten everywhere: in any order.
func TestSync_ForgottenRestored(t *testing.T) {
	t.Parallel()
	for replacer, by := range []string{"laptop", "desktop"} {
		for name, order := range orders(2) {
			t.Run(fmt.Sprintf("replaced on the %s, %s", by, name), func(t *testing.T) {
				t.Parallel()
				cs, paths, f := computers(t, 2)
				laptop, desktop := cs[0], cs[1]
				gh := laptop.put("github", "pw-old")
				settleN(t, f, 6, cs...)
				laptop.put("github", "pw-laptop")
				forgetOld(t, laptop, gh)
				// The desktop's backup, before it has the forgetting.
				backup := filepath.Join(t.TempDir(), "backup.db")
				if err := database.CopyTo(paths[1], backup); err != nil {
					t.Fatal(err)
				}
				settleN(t, f, 6, cs...)
				syncLoose(desktop, f)
				if err := database.RestoreInPlace(paths[1], backup); err != nil {
					t.Fatal(err)
				}
				settleN(t, f, 6, inOrder(cs, order)...)
				for _, c := range cs {
					if got := c.secret(gh); got != "pw-old" {
						t.Errorf("%s: after the restore the password is %s, want pw-old", c.name, got)
					}
				}
				cs[replacer].put("github", "pw-next")
				settleN(t, f, 6, inOrder(cs, order)...)
				for _, c := range cs {
					if got := c.secret(gh); got != "pw-next" {
						t.Errorf("%s: the password is %s, want pw-next", c.name, got)
					}
				}
				oldGone(t, cs)
			})
		}
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
			oldGone(t, cs)
		})
	}
}

// A password forgotten, then typed again, met with a restore elsewhere
// holding its use from before the forget: the use typed again counts, so
// it's kept once replaced (decided with the user).
func TestSync_ForgottenRetypedRestoredElsewhere(t *testing.T) {
	t.Parallel()
	for replacer, by := range []string{"laptop", "desktop"} {
		t.Run("replaced on the "+by, func(t *testing.T) {
			t.Parallel()
			cs, paths, f := computers(t, 2)
			laptop, desktop := cs[0], cs[1]
			gh := laptop.put("github", "pw-old")
			settleN(t, f, 6, cs...)
			backup := filepath.Join(t.TempDir(), "backup.db")
			if err := database.CopyTo(paths[1], backup); err != nil {
				t.Fatal(err)
			}
			laptop.put("github", "pw-laptop")
			forgetOld(t, laptop, gh)
			settleN(t, f, 6, cs...)
			// Typed again on the laptop; the desktop's restore reaches the
			// folder first.
			laptop.put("github", "pw-old")
			if err := database.RestoreInPlace(paths[1], backup); err != nil {
				t.Fatal(err)
			}
			syncLoose(desktop, f)
			settleN(t, f, 6, cs...)
			cs[replacer].put("github", "pw-next")
			settleN(t, f, 6, cs...)
			oldKept(t, cs)
		})
	}
}

// Forgetting one use of a password forgets that one, not a later use of
// the same password, on every computer.
func TestSync_ForgetOneUse(t *testing.T) {
	t.Parallel()
	cs, _, f := computers(t, 2)
	laptop := cs[0]
	var gh vault.Key
	for _, pw := range []string{"pw-old", "pw-mid", "pw-old", "pw-new"} {
		gh = laptop.put("github", pw)
		time.Sleep(10 * time.Millisecond)
	}
	settleN(t, f, 6, cs...)
	// Versions: 1 pw-new, 2 pw-old (the later use), 3 pw-mid, 4 pw-old.
	if err := laptop.store.ForgetVersions(gh, 4); err != nil {
		t.Fatal(err)
	}
	settleN(t, f, 6, cs...)
	for _, c := range cs {
		if n := strings.Count(strings.Join(historySecrets(t, c), " "), "pw-old"); n != 1 {
			t.Errorf("%s: pw-old in its history %d times, want the later use only", c.name, n)
		}
	}
}

// Forgetting a later use of a password, then an earlier one, keeps both
// forgotten on every computer.
func TestSync_ForgetBothUses(t *testing.T) {
	t.Parallel()
	cs, _, f := computers(t, 2)
	laptop := cs[0]
	var gh vault.Key
	for _, pw := range []string{"pw-old", "pw-mid", "pw-old", "pw-new"} {
		gh = laptop.put("github", pw)
		time.Sleep(10 * time.Millisecond)
	}
	settleN(t, f, 6, cs...)
	// Versions: 1 pw-new, 2 pw-old (the later use), 3 pw-mid, 4 pw-old.
	if err := laptop.store.ForgetVersions(gh, 2); err != nil {
		t.Fatal(err)
	}
	// Now 3 is the earlier use.
	if err := laptop.store.ForgetVersions(gh, 3); err != nil {
		t.Fatal(err)
	}
	settleN(t, f, 6, cs...)
	oldGone(t, cs)
}
