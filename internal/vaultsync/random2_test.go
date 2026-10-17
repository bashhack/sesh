package vaultsync

import (
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/bashhack/sesh/internal/database"
	"github.com/bashhack/sesh/internal/vault"
)

// TestSync_Random with restores from backups, writes never agreed, unequal
// history.keep, damaged rows and forgetting: the first computer, keeping
// everything, still has every secret it held but those deleted or
// forgotten on purpose (SESH_SYNC_SEEDS, SESH_SYNC_STEPS for more).
func TestSync_Random2(t *testing.T) {
	if raceDetector {
		t.Skip("too slow with -race; run without it")
	}
	seeds, steps := 2, 40
	if s := os.Getenv("SESH_SYNC_SEEDS"); s != "" {
		fmt.Sscan(s, &seeds) //nolint:errcheck // test
	}
	if s := os.Getenv("SESH_SYNC_STEPS"); s != "" {
		fmt.Sscan(s, &steps) //nolint:errcheck // test
	}
	only := os.Getenv("SESH_SYNC_SEED")
	for seed := range seeds {
		if only != "" && only != fmt.Sprint(seed) {
			continue
		}
		t.Run(fmt.Sprint(seed), func(t *testing.T) {
			r := rand.New(rand.NewPCG(uint64(seed), 11))
			cs, paths, f := computers(t, 3)
			cs[0].store.SetHistoryKeep(1000)
			keeps := []int{1000, r.IntN(3), r.IntN(3)}
			cs[1].store.SetHistoryKeep(keeps[1])
			cs[2].store.SetHistoryKeep(keeps[2])
			var set []string
			excused := map[string]bool{}
			forgottenSecrets := map[string]bool{}
			backups := map[int]string{}
			n := 0
			var log []string
			logf := func(format string, a ...any) { log = append(log, fmt.Sprintf(format, a...)) }
			logf("keeps %v", keeps)
			confirm := func(sec string) {
				syncLoose(cs[0], f)
				if slices.Contains(allSecrets(t, cs[0]), sec) {
					set = append(set, sec)
				}
			}
			reported := map[string]bool{}
			check := func(step int) {
				all := allSecrets(t, cs[0])
				for _, s := range set {
					if !slices.Contains(all, s) && !excused[s] && !reported[s] {
						reported[s] = true
						t.Errorf("STEPLOSS after step %d: laptop no longer has %s", step, s)
					}
				}
			}
			for step := range steps {
				check(step - 1)
				ci := r.IntN(len(cs))
				c := cs[ci]
				keys := liveKeys(t, c)
				op := r.IntN(14)
				switch {
				case op < 3 || len(keys) == 0:
					svc := fmt.Sprintf("s%d", r.IntN(4))
					n++
					sec := fmt.Sprintf("%s-%d", c.name, n)
					k := vault.Key{Kind: vault.KindPassword, Service: svc, Username: "alice"}
					if err := c.store.Put(k, []byte(sec)); err == nil {
						logf("%d %s put %s %s", step, c.name, svc, sec)
						if ci == 0 {
							set = append(set, sec)
						} else {
							syncLoose(c, f)
							confirm(sec)
						}
					}
					continue
				case op < 5:
					k := keys[r.IntN(len(keys))]
					to := vault.Key{Kind: k.Kind, Service: fmt.Sprintf("s%d", r.IntN(6)), Username: k.Username}
					if _, err := c.store.Edit(k, database.EntryEdit{To: &to}); err == nil {
						logf("%d %s rename %s -> %s", step, c.name, k.Service, to.Service)
					}
				case op < 6:
					k := keys[r.IntN(len(keys))]
					if err := c.store.Delete(k); err == nil {
						logf("%d %s trash %s", step, c.name, k.Service)
					}
				case op < 7:
					tr, _ := c.store.Trash() //nolint:errcheck // test
					if len(tr) > 0 {
						e := tr[r.IntN(len(tr))]
						if _, err := c.store.RestoreFromTrash(e.ID, vault.Key{}); err == nil {
							logf("%d %s untrash %s", step, c.name, e.Service)
						}
					}
				case op < 8:
					k := keys[r.IntN(len(keys))]
					_ = c.store.SetDetails(k, &vault.Details{Notes: []byte(fmt.Sprintf("note %d", step))}) //nolint:errcheck // test
					logf("%d %s notes %s", step, c.name, k.Service)
				case op < 9:
					logf("%d %s sync racing", step, c.name)
					syncRacing(c, f, step)
					continue
				case op < 10:
					// A backup, or (on cs[1], cs[2]) a restore of one.
					if ci == 0 {
						continue
					}
					if b, ok := backups[ci]; ok && r.IntN(2) == 0 {
						syncLoose(c, f)
						if err := database.RestoreInPlace(paths[ci], b); err != nil {
							t.Fatal(err)
						}
						logf("%d %s restore", step, c.name)
					} else {
						b := filepath.Join(t.TempDir(), fmt.Sprintf("b%d-%d.db", ci, step))
						if err := database.CopyTo(paths[ci], b); err != nil {
							t.Fatal(err)
						}
						backups[ci] = b
						logf("%d %s backup", step, c.name)
					}
					continue
				case op < 11:
					// A write never agreed.
					k := keys[r.IntN(len(keys))]
					writeOnly(t, c, f, liveUID(t, c, k))
					logf("%d %s write-only %s", step, c.name, k.Service)
					continue
				case op < 12:
					// Damage, on cs[1] or cs[2].
					if ci == 0 {
						continue
					}
					switch r.IntN(3) {
					case 0:
						rawExec(t, paths[ci], `UPDATE history SET encrypted_data = zeroblob(40) WHERE id = (SELECT id FROM history ORDER BY random() LIMIT 1)`)
						logf("%d %s damage a history row", step, c.name)
					case 1:
						rawExec(t, paths[ci], `UPDATE sync_state SET base = x'00' WHERE uid = (SELECT uid FROM sync_state ORDER BY random() LIMIT 1)`)
						logf("%d %s damage a base", step, c.name)
					default:
						rawExec(t, paths[ci], `UPDATE trash SET tags = 'not json' WHERE id = (SELECT id FROM trash ORDER BY random() LIMIT 1)`)
						logf("%d %s damage trash tags", step, c.name)
					}
					continue
				case op < 13:
					// Forget the newest earlier secret.
					k := keys[r.IntN(len(keys))]
					rec, _, err := c.store.SyncRecord(liveUID(t, c, k), "x")
					if err != nil || len(rec.History) == 0 {
						continue
					}
					sec := string(rec.History[0].Secret)
					if err := c.store.ForgetVersions(k, 2); err == nil {
						excused[sec] = true
						forgottenSecrets[sec] = true
						logf("%d %s forget %s on %s", step, c.name, sec, k.Service)
					}
					continue
				default:
					// Purge.
					k := keys[r.IntN(len(keys))]
					uid := liveUID(t, c, k)
					for _, o := range cs {
						rec, _, err := o.store.SyncRecord(uid, "x")
						if err != nil || !rec.Purged.IsZero() {
							continue
						}
						excused[string(rec.Secret)] = true
						for _, h := range rec.History {
							excused[string(h.Secret)] = true
						}
					}
					if err := c.store.PurgeMany([]vault.Key{k}); err == nil {
						logf("%d %s purge %s", step, c.name, k.Service)
					}
				}
				if r.IntN(2) == 0 {
					logf("%d %s sync", step, c.name)
					syncLoose(c, f)
				}
			}
			settled := false
			var last []string
			for range 14 {
				quiet := true
				last = nil
				for _, c := range cs {
					s := syncLoose(c, f)
					if !s.Nothing() {
						quiet = false
						last = append(last, c.name+": "+s.String()+fmt.Sprintf(" %q", s.Problems))
					}
				}
				if quiet {
					settled = true
					break
				}
			}
			if !settled {
				t.Errorf("never settled; last round: %q", last)
			}
			for _, c := range cs[1:] {
				sameVaults(t, cs[0], c)
			}
			all := allSecrets(t, cs[0])
			for _, s := range set {
				if !slices.Contains(all, s) && !excused[s] {
					t.Errorf("laptop (keeps all): secret %s lost", s)
				}
			}
			back := false
			for _, c := range cs {
				for _, s := range historySecrets(t, c) {
					if forgottenSecrets[s] {
						t.Logf("FORGOT-BACK %s: forgotten %s is back", c.name, s)
						back = true
					}
				}
			}
			if t.Failed() || back {
				t.Logf("log:\n%s", strings.Join(log, "\n"))
			}
		})
	}
}

func liveUID(t *testing.T, c *computer, k vault.Key) string {
	t.Helper()
	items, err := c.store.SyncItems()
	if err != nil {
		t.Fatal(err)
	}
	for _, it := range items {
		if it.Key == k && it.Place == database.SyncLive {
			return it.UID
		}
	}
	t.Fatalf("%s: no live %s", c.name, k)
	return ""
}

func historySecrets(t *testing.T, c *computer) []string {
	items, _ := c.store.SyncItems() //nolint:errcheck // probe
	var out []string
	for _, it := range items {
		if it.Place == database.SyncGone {
			continue
		}
		r, _, err := c.store.SyncRecord(it.UID, "x")
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, secrets(r.History)...)
	}
	return out
}
