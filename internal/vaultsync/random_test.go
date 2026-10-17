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
	"github.com/bashhack/sesh/internal/syncfolder"
	"github.com/bashhack/sesh/internal/vault"
)

func liveKeys(t *testing.T, c *computer) []vault.Key {
	items, err := c.store.SyncItems()
	if err != nil {
		t.Fatal(err)
	}
	var out []vault.Key
	for _, it := range items {
		if it.Place == database.SyncLive {
			out = append(out, it.Key)
		}
	}
	return out
}

// syncRacing syncs c as if another computer wrote at once: files c writes
// over others' land as conflict copies, the others' kept as the files.
func syncRacing(c *computer, f syncfolder.Folder, n int) {
	dir := filepath.Join(f.Dir(), "entries")
	before := map[string][]byte{}
	des, _ := os.ReadDir(dir) //nolint:errcheck // test
	for _, d := range des {
		if strings.HasSuffix(d.Name(), ".sesh") && !strings.Contains(d.Name(), " ") {
			b, _ := os.ReadFile(filepath.Join(dir, d.Name())) //nolint:errcheck // test
			before[d.Name()] = b
		}
	}
	syncLoose(c, f)
	des, _ = os.ReadDir(dir) //nolint:errcheck // test
	for _, d := range des {
		old, ok := before[d.Name()]
		if !ok {
			continue
		}
		b, _ := os.ReadFile(filepath.Join(dir, d.Name())) //nolint:errcheck // test
		if string(b) != string(old) {
			_ = os.WriteFile(filepath.Join(dir, strings.TrimSuffix(d.Name(), ".sesh")+fmt.Sprintf(" (%s's conflicted copy %d).sesh", c.name, n)), b, 0o600) //nolint:errcheck // test
			_ = os.WriteFile(filepath.Join(dir, d.Name()), old, 0o600)                                                                                      //nolint:errcheck // test
		}
	}
}

// Random changes on three computers, with sync tools' copies, lost files and
// older copies put back, settle to the same vaults, losing no secret not
// deleted on purpose (SESH_SYNC_SEEDS runs more).
func TestSync_Random(t *testing.T) {
	if raceDetector {
		t.Skip("too slow with -race; run without it")
	}
	seeds := 3
	if s := os.Getenv("SESH_SYNC_SEEDS"); s != "" {
		fmt.Sscan(s, &seeds) //nolint:errcheck // test
	}
	for seed := range seeds {
		t.Run(fmt.Sprint(seed), func(t *testing.T) {
			r := rand.New(rand.NewPCG(uint64(seed), 7))
			cs, _, f := computers(t, 3)
			for _, c := range cs {
				c.store.SetHistoryKeep(1000)
			}
			var set []string
			purged := map[string]bool{}
			snaps := map[string][][]byte{}
			n := 0
			var log []string
			for step := range 40 {
				c := cs[r.IntN(len(cs))]
				keys := liveKeys(t, c)
				op := r.IntN(10)
				if step%3 == 0 {
					dir := filepath.Join(f.Dir(), "entries")
					des, _ := os.ReadDir(dir) //nolint:errcheck // test
					for _, d := range des {
						b, _ := os.ReadFile(filepath.Join(dir, d.Name())) //nolint:errcheck // test
						snaps[d.Name()] = append(snaps[d.Name()], b)
					}
				}
				switch {
				case op < 3 || len(keys) == 0:
					svc := fmt.Sprintf("s%d", r.IntN(4))
					n++
					sec := fmt.Sprintf("%s-%d", c.name, n)
					k := vault.Key{Kind: vault.KindPassword, Service: svc, Username: "alice"}
					if err := c.store.Put(k, []byte(sec)); err == nil {
						set = append(set, sec)
						log = append(log, fmt.Sprintf("%d %s put %s %s", step, c.name, svc, sec))
					}
				case op < 5:
					k := keys[r.IntN(len(keys))]
					to := vault.Key{Kind: k.Kind, Service: fmt.Sprintf("s%d", r.IntN(6)), Username: k.Username}
					if _, err := c.store.Edit(k, database.EntryEdit{To: &to}); err == nil {
						log = append(log, fmt.Sprintf("%d %s rename %s -> %s", step, c.name, k.Service, to.Service))
					}
				case op < 6:
					k := keys[r.IntN(len(keys))]
					if err := c.store.Delete(k); err == nil {
						log = append(log, fmt.Sprintf("%d %s trash %s", step, c.name, k.Service))
					}
				case op < 7:
					tr, _ := c.store.Trash() //nolint:errcheck // test
					if len(tr) > 0 {
						e := tr[r.IntN(len(tr))]
						if _, err := c.store.RestoreFromTrash(e.ID, vault.Key{}); err == nil {
							log = append(log, fmt.Sprintf("%d %s untrash %s", step, c.name, e.Service))
						}
					}
				case op < 8:
					k := keys[r.IntN(len(keys))]
					_ = c.store.SetDetails(k, &vault.Details{Notes: []byte(fmt.Sprintf("note %d", step))}) //nolint:errcheck // test
					log = append(log, fmt.Sprintf("%d %s notes %s", step, c.name, k.Service))
				case op < 9:
					log = append(log, fmt.Sprintf("%d %s sync racing", step, c.name))
					syncRacing(c, f, step)
					continue
				case op < 10:
					dir := filepath.Join(f.Dir(), "entries")
					des, _ := os.ReadDir(dir) //nolint:errcheck // test
					if len(des) == 0 {
						continue
					}
					d := des[r.IntN(len(des))]
					p := filepath.Join(dir, d.Name())
					switch r.IntN(4) {
					case 0:
						_ = os.Remove(p) //nolint:errcheck // test
						log = append(log, fmt.Sprintf("%d lost %s", step, d.Name()))
					case 1:
						if old := snaps[d.Name()]; len(old) > 0 {
							_ = os.WriteFile(p, old[r.IntN(len(old))], 0o600) //nolint:errcheck // test
							log = append(log, fmt.Sprintf("%d older put back %s", step, d.Name()))
						}
					case 2:
						if len(keys) > 0 && r.IntN(2) == 0 {
							k := keys[r.IntN(len(keys))]
							rec, _, _ := c.store.SyncRecord(uidOfKey(t, c, k), "x") //nolint:errcheck // test
							purged[string(rec.Secret)] = true
							for _, h := range rec.History {
								purged[string(h.Secret)] = true
							}
							if err := c.store.PurgeMany([]vault.Key{k}); err == nil {
								log = append(log, fmt.Sprintf("%d %s purge %s", step, c.name, k.Service))
							}
						}
					default:
						b, _ := os.ReadFile(p) //nolint:errcheck // test
						snaps[d.Name()] = append(snaps[d.Name()], b)
					}
					continue
				}
				if r.IntN(2) == 0 {
					log = append(log, fmt.Sprintf("%d %s sync", step, c.name))
					syncLoose(c, f)
				}
			}
			// Settle.
			settled := false
			for round := range 12 {
				quiet := true
				for _, c := range cs {
					s := syncLoose(c, f)
					if len(s.Problems) > 0 {
						t.Errorf("%s problems: %q", c.name, s.Problems)
					}
					if !s.Nothing() {
						quiet = false
					}
				}
				if quiet {
					settled = true
					_ = round
					break
				}
			}
			if !settled {
				t.Errorf("never settled")
			}
			for _, c := range cs[1:] {
				sameVaults(t, cs[0], c)
			}
			for _, c := range cs {
				var all []string
				items, _ := c.store.SyncItems() //nolint:errcheck // test
				for _, it := range items {
					if it.Place == database.SyncGone {
						continue
					}
					rec, _, err := c.store.SyncRecord(it.UID, "x")
					if err != nil {
						t.Fatal(err)
					}
					all = append(all, string(rec.Secret))
					all = append(all, secrets(rec.History)...)
				}
				for _, s := range set {
					if !slices.Contains(all, s) && !purged[s] {
						t.Errorf("%s: secret %s lost", c.name, s)
					}
				}
			}
			if t.Failed() {
				t.Logf("log:\n%s", strings.Join(log, "\n"))
			}
		})
	}
}
