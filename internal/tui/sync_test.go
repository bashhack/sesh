package tui

import (
	"strings"
	"testing"
	"time"
)

// syncApp is an app whose vault syncs: each sync's reason goes in hows,
// and it says what said holds then.
func syncApp(t *testing.T, f *fakeVault) (a *app, hows *[]SyncHow, said *[]string) {
	t.Helper()
	hows, said = &[]SyncHow{}, &[]string{}
	a = newApp(t, f, Options{
		Sync: func(_ Vault, how SyncHow) ([]string, bool) {
			*hows = append(*hows, how)
			return *said, true
		},
		Syncing: func() bool { return true },
	})
	return a, hows, said
}

// The app takes what changed elsewhere as it starts and every 5 minutes,
// and looks for its own changes to send every few seconds.
func TestSync_WhenTheAppSyncs(t *testing.T) {
	a, hows, _ := syncApp(t, newFake())
	a.tick(time.Second)
	a.tick(time.Second)
	a.tick(pushEvery)
	a.tick(syncEvery)
	want := []SyncHow{SyncPull, SyncPush, SyncPull}
	if len(*hows) != len(want) {
		t.Fatalf("synced %v, want %v", *hows, want)
	}
	for i := range want {
		if (*hows)[i] != want[i] {
			t.Errorf("sync %d: %v, want %v", i, (*hows)[i], want[i])
		}
	}
}

// What a sync did is said in the status line, a warning as gone wrong.
func TestSync_SaysWhatItDid(t *testing.T) {
	a, _, said := syncApp(t, newFake())
	*said = []string{"Synced: 1 taken."}
	a.tick(time.Second)
	if !strings.Contains(a.screen(), "Synced: 1 taken.") || a.statusBad {
		t.Errorf("after a sync:\n%s", a.screen())
	}
	*said = []string{"⚠️  Sync: the master password was changed on another computer; nothing syncs until sesh sync takes it."}
	a.tick(syncEvery)
	if !a.statusBad || !strings.Contains(a.status, "nothing syncs until sesh sync takes it") {
		t.Errorf("a warning: %q, bad %v", a.status, a.statusBad)
	}
}

// A sync taking changes with a panel open closes it, saying why.
func TestSync_ChangesClosePanel(t *testing.T) {
	f := newFake()
	a, _, _ := syncApp(t, f)
	a.press("ctrl+g")
	if a.ov == nil {
		t.Fatal("the sesh menu didn't open")
	}
	f.changed = true
	a.tick(time.Second)
	if a.ov != nil || !strings.Contains(a.status, "A sync took changes from another computer") {
		t.Errorf("after a sync taking changes: panel %v, %q", a.ov != nil, a.status)
	}
}

// Ctrl-G's menu syncs now when the vault syncs, and doesn't offer it
// when it doesn't.
func TestSync_SyncNow(t *testing.T) {
	a, hows, said := syncApp(t, newFake())
	a.tick(time.Second)
	*said = []string{"In sync with ~/sync: nothing to do."}
	a.press("ctrl+g")
	if !strings.Contains(a.screen(), "sync now (last ") {
		t.Fatalf("the sesh menu:\n%s", a.screen())
	}
	a.press("s")
	if n := len(*hows); n != 2 || (*hows)[1] != SyncNow || !strings.Contains(a.status, "nothing to do") {
		t.Errorf("sync now: %v, %q", *hows, a.status)
	}

	b := newApp(t, newFake(), Options{Sync: func(Vault, SyncHow) ([]string, bool) { return nil, false }, Syncing: func() bool { return false }})
	b.press("ctrl+g")
	if strings.Contains(b.screen(), "sync now") {
		t.Errorf("sync now offered for a vault that doesn't sync:\n%s", b.screen())
	}
}

// Unlocked again, the app takes what changed meanwhile at once.
func TestSync_PullsAfterUnlock(t *testing.T) {
	f := newFake()
	var hows []SyncHow
	a := newApp(t, f, Options{
		Sync:    func(_ Vault, how SyncHow) ([]string, bool) { hows = append(hows, how); return nil, true },
		Syncing: func() bool { return true },
		Unlock:  func([]byte) (Vault, error) { return f, nil },
	})
	a.tick(time.Second)
	a.lock("test")
	a.press("pw", "enter")
	a.tick(time.Second)
	if len(hows) != 2 || hows[1] != SyncPull {
		t.Errorf("synced %v, want a pull after the unlock", hows)
	}
}

// A lock while a sync waits to run doesn't leave the app never syncing
// again.
func TestSync_LockMidSync(t *testing.T) {
	f := newFake()
	var hows []SyncHow
	a := newApp(t, f, Options{
		Sync:    func(_ Vault, how SyncHow) ([]string, bool) { hows = append(hows, how); return nil, true },
		Syncing: func() bool { return true },
		Unlock:  func([]byte) (Vault, error) { return f, nil },
	})
	a.now = a.now.Add(time.Second)
	_, pending := a.Update(tickMsg(a.now))
	a.lock("test")
	a.run(pending)
	a.press("pw", "enter")
	a.tick(time.Second)
	if len(hows) != 1 || hows[0] != SyncPull || a.syncing {
		t.Errorf("after a lock mid-sync: synced %v, syncing %v", hows, a.syncing)
	}
}

// With sync.auto off the app doesn't sync on its own, and sync now says
// when it last did only once it has.
func TestSync_AutoOff(t *testing.T) {
	var hows []SyncHow
	a := newApp(t, newFake(), Options{
		Sync:     func(_ Vault, how SyncHow) ([]string, bool) { hows = append(hows, how); return nil, how == SyncNow },
		Syncing:  func() bool { return true },
		AutoSync: func() bool { return false },
	})
	a.tick(time.Second)
	a.tick(syncEvery)
	a.press("ctrl+g")
	if len(hows) != 0 || strings.Contains(a.screen(), "(last ") {
		t.Fatalf("with sync.auto off: synced %v\n%s", hows, a.screen())
	}
	a.press("s")
	a.press("ctrl+g")
	if len(hows) != 1 || !strings.Contains(a.screen(), "sync now (last ") {
		t.Errorf("sync now: %v\n%s", hows, a.screen())
	}
}

// An import being previewed or written holds the app's syncs.
func TestSync_HeldByImport(t *testing.T) {
	a, hows, _ := syncApp(t, newFake())
	a.importing = &importing{}
	a.tick(time.Second)
	if len(*hows) != 0 {
		t.Errorf("synced during an import: %v", *hows)
	}
	a.importing = nil
	a.tick(time.Second)
	if len(*hows) != 1 {
		t.Errorf("after the import: %v", *hows)
	}
}

// The menu's "last" is when a sync ran, not when one was looked for.
func TestSync_LastOnlyWhenRan(t *testing.T) {
	a := newApp(t, newFake(), Options{Sync: func(Vault, SyncHow) ([]string, bool) { return nil, false }, Syncing: func() bool { return true }})
	a.tick(time.Second)
	a.tick(pushEvery)
	a.press("ctrl+g")
	if strings.Contains(a.screen(), "(last ") {
		t.Errorf("no sync ran, but:\n%s", a.screen())
	}
}

// A sync under way isn't joined by another.
func TestSync_OneAtATime(t *testing.T) {
	var hows []SyncHow
	a := newApp(t, newFake(), Options{
		Sync:    func(_ Vault, how SyncHow) ([]string, bool) { hows = append(hows, how); return nil, true },
		Syncing: func() bool { return true },
	})
	a.now = a.now.Add(time.Second)
	_, first := a.Update(tickMsg(a.now))
	a.now = a.now.Add(syncEvery)
	_, second := a.Update(tickMsg(a.now))
	a.run(first)
	a.run(second)
	if len(hows) != 1 {
		t.Errorf("synced %v, want one at a time", hows)
	}
}
