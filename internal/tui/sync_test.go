package tui

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
)

// syncApp is an app whose vault syncs: each sync's reason goes in hows,
// and it says what said holds then.
func syncApp(t *testing.T, f *fakeVault) (a *app, hows *[]SyncHow, said *[]string) {
	t.Helper()
	hows, said = &[]SyncHow{}, &[]string{}
	a = newApp(t, f, Options{
		Sync: func(_ Vault, how SyncHow) ([]string, []string, bool) {
			*hows = append(*hows, how)
			return *said, *said, true
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

	b := newApp(t, newFake(), Options{Sync: func(Vault, SyncHow) ([]string, []string, bool) { return nil, nil, false }, Syncing: func() bool { return false }})
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
		Sync:    func(_ Vault, how SyncHow) ([]string, []string, bool) { hows = append(hows, how); return nil, nil, true },
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
		Sync:    func(_ Vault, how SyncHow) ([]string, []string, bool) { hows = append(hows, how); return nil, nil, true },
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
		Sync: func(_ Vault, how SyncHow) ([]string, []string, bool) {
			hows = append(hows, how)
			return nil, nil, how == SyncNow
		},
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
	a := newApp(t, newFake(), Options{Sync: func(Vault, SyncHow) ([]string, []string, bool) { return nil, nil, false }, Syncing: func() bool { return true }})
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
		Sync:    func(_ Vault, how SyncHow) ([]string, []string, bool) { hows = append(hows, how); return nil, nil, true },
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

// The settings panel has a sync row: off, or the folder and when the app
// last synced; Enter shows what sesh sync status says, with syncing now.
func TestSync_Row(t *testing.T) {
	state := SyncState{Said: "off"}
	a := newApp(t, newFake(), Options{
		Settings:  func() ([]Setting, error) { return nil, nil },
		SyncState: func() (SyncState, error) { return state, nil },
		Sync:      func(Vault, SyncHow) ([]string, []string, bool) { return nil, nil, true },
		Syncing:   func() bool { return state.On },
	})
	a.press("ctrl+g", ",")
	if s := a.screen(); !strings.Contains(s, "Sync                      off") || !strings.Contains(s, "sesh sync init <folder>") {
		t.Fatalf("not syncing:\n%s", s)
	}
	a.press("esc", "esc")
	state = SyncState{Said: "~/sync", On: true, Lines: []string{"Sync folder:   ~/sync", "Changed here, to send:          2", "⚠️  1 entry's file is sealed with another master password's key: sync leaves it for the computer that wrote it"}}
	a.tick(time.Second)
	a.press("ctrl+g", ",")
	if s := a.screen(); !strings.Contains(s, "Sync                      ~/sync, synced ") {
		t.Fatalf("syncing:\n%s", s)
	}
	a.press("enter")
	if s := a.screen(); a.ov == nil || a.ov.title != "Sync" || !strings.Contains(s, "Changed here, to send:          2") || !strings.Contains(s, "1 entry's file is sealed") || !strings.Contains(s, "sync now") {
		t.Errorf("the sync panel:\n%s", s)
	}
}

// Every line the last sync that said something said is kept for its
// panel, from the sync panel and Ctrl-G's menu; a quiet sync after keeps
// them.
func TestSync_Results(t *testing.T) {
	a, _, said := syncApp(t, newFake())
	*said = []string{"Synced: 2 taken, 1 sent.", "⚠️  Sync: 1 entry (password/bank/alice) made here, whose secret this vault no longer has as typed here: not sent until it's typed again here."}
	a.tick(time.Second)
	*said = nil
	a.tick(syncEvery)
	a.press("ctrl+g")
	if !strings.Contains(a.screen(), "last sync's results (") {
		t.Fatalf("Ctrl-G's menu:\n%s", a.screen())
	}
	a.press("y")
	if s := a.screen(); a.ov == nil || !strings.HasPrefix(a.ov.title, "Last sync's results, ") || !strings.Contains(s, "Synced: 2 taken, 1 sent.") || !strings.Contains(s, "password/bank/alice") {
		t.Errorf("the results:\n%s", s)
	}
}

// Sync's state that can't be read is said in its row: the rest of the
// settings panel stays.
func TestSync_RowError(t *testing.T) {
	a := newApp(t, newFake(), Options{
		Settings: func() ([]Setting, error) { return []Setting{{Key: "history.keep", Value: "10"}}, nil },
		SyncState: func() (SyncState, error) {
			return SyncState{Said: "~/sync", On: true}, errors.New("read the sync folder: entries isn't a folder")
		},
	})
	a.press("ctrl+g", ",")
	if s := a.screen(); !strings.Contains(s, "history.keep") || !strings.Contains(s, "Sync                      ~/sync") {
		t.Fatalf("the panel:\n%s", s)
	}
	a.press("enter")
	if s := a.screen(); !strings.Contains(s, "entries isn't a folder") {
		t.Errorf("the sync panel:\n%s", s)
	}
}

// The results keep a warning the status line leaves out, said already
// today; locking forgets them; sync now keeps the sync panel open.
func TestSync_ResultsWhole(t *testing.T) {
	warn := "⚠️  Sync: 1 entry (password/bank/alice) made here, whose secret this vault no longer has as typed here: not sent until it's typed again here."
	a := newApp(t, newFake(), Options{
		Settings: func() ([]Setting, error) { return nil, nil },
		SyncState: func() (SyncState, error) {
			return SyncState{Said: "~/sync", On: true, Lines: []string{"Sync folder:   ~/sync"}}, nil
		},
		Sync: func(Vault, SyncHow) ([]string, []string, bool) {
			return []string{"Synced: 1 sent."}, []string{"Synced: 1 sent.", warn}, true
		},
		Syncing: func() bool { return true },
	})
	a.tick(time.Second)
	if strings.Contains(a.status, "password/bank") {
		t.Errorf("status %q: want the warning left out", a.status)
	}
	a.press("ctrl+g", "y")
	if !strings.Contains(a.screen(), "password/bank/alice") {
		t.Fatalf("the results:\n%s", a.screen())
	}
	a.press("esc", "esc", "ctrl+g", ",", "enter", "s")
	if a.ov == nil || a.ov.title != "Sync" {
		t.Errorf("after sync now: panel %+v", a.ov)
	}
	a.press("esc", "esc", "esc", "ctrl+g", "l")
	if a.v != nil || a.lastSaid != nil {
		t.Errorf("after locking: unlocked %v, results kept %q", a.v != nil, a.lastSaid)
	}
}

// A line the row cuts is said whole below it, however narrow the window;
// one it doesn't cut isn't said again.
func TestSync_LineWholeWhenCut(t *testing.T) {
	long := "⚠️  1 entry waits for the sync tool to fetch its file: keep the folder downloaded"
	a := newApp(t, newFake(), Options{
		Settings: func() ([]Setting, error) { return nil, nil },
		SyncState: func() (SyncState, error) {
			return SyncState{Said: "~/sync", On: true, Lines: []string{"Sync folder:   ~/sync", long}}, nil
		},
		Sync:    func(Vault, SyncHow) ([]string, []string, bool) { return nil, nil, true },
		Syncing: func() bool { return true },
	})
	a.Update(tea.WindowSizeMsg{Width: 60, Height: 30})
	a.press("ctrl+g", ",", "enter")
	if s := a.screen(); strings.Count(s, "Sync folder:   ~/sync") != 1 {
		t.Errorf("a short line, selected:\n%s", s)
	}
	a.press("down")
	if s := a.screen(); !strings.Contains(s, "keep the folder downloaded") {
		t.Errorf("a cut line, selected, at 60 wide:\n%s", s)
	}
}

// Not syncing, the sync row asks for a folder and starts syncing through
// it; syncing, the sync panel leaves after asking.
func TestSync_StartAndLeave(t *testing.T) {
	on := false
	var started, left []string
	a := newApp(t, newFake(), Options{
		Settings: func() ([]Setting, error) { return nil, nil },
		SyncState: func() (SyncState, error) {
			if on {
				return SyncState{Said: "~/sync", On: true, Lines: []string{"Sync folder:   ~/sync"}}, nil
			}
			return SyncState{Said: "off"}, nil
		},
		StartSync: func(_ Vault, dir string) (string, error) {
			started = append(started, dir)
			on = true
			return "Made the sync folder " + dir + ".", nil
		},
		SyncFolderOffer: func() string { return "~/icloud/sesh-sync" },
		LeaveSync: func() (string, error) {
			left = append(left, "x")
			on = false
			return "This vault no longer syncs with ~/sync.", nil
		},
		Sync:    func(Vault, SyncHow) ([]string, []string, bool) { return nil, nil, true },
		Syncing: func() bool { return on },
	})
	a.press("ctrl+g", ",", "enter")
	if a.form == nil || !strings.Contains(a.screen(), "~/icloud/sesh-sync") {
		t.Fatalf("starting:\n%s", a.screen())
	}
	a.press("ctrl+u", "enter")
	if a.form == nil || !strings.Contains(a.form.err, "Type the folder") || len(started) != 0 {
		t.Fatalf("nothing typed: started %q, form %+v", started, a.form)
	}
	a.press("sync", "enter")
	if a.form == nil || !strings.Contains(a.form.err, "full path") || len(started) != 0 {
		t.Fatalf("a relative path: started %q, form %+v", started, a.form)
	}
	a.press("ctrl+u")
	a.press("~/sync", "enter")
	if !slices.Equal(started, []string{"~/sync"}) || !strings.Contains(a.screen(), "Made the sync folder ~/sync.") {
		t.Fatalf("started %q:\n%s", started, a.screen())
	}
	if !strings.Contains(a.screen(), "Sync                      ~/sync") {
		t.Errorf("the row after starting:\n%s", a.screen())
	}
	a.press("enter", "x")
	if a.ov == nil || a.ov.kind != panelConfirm || !a.ov.danger || len(left) != 0 {
		t.Fatalf("leave asks first: left %q, panel %+v", left, a.ov)
	}
	a.tick(confirmAfter)
	a.press("y")
	if len(left) != 1 || !strings.Contains(a.screen(), "no longer syncs") || !strings.Contains(a.screen(), "Sync                      off") {
		t.Errorf("left %q:\n%s", left, a.screen())
	}
}

// Locked before starting to sync could run, the app's own syncs go on
// after: the start still ends.
func TestSync_StartLockedFirst(t *testing.T) {
	a := newApp(t, newFake(), Options{
		Settings:  func() ([]Setting, error) { return nil, nil },
		SyncState: func() (SyncState, error) { return SyncState{Said: "off"}, nil },
		StartSync: func(Vault, string) (string, error) { return "Made it.", nil },
		Sync:      func(Vault, SyncHow) ([]string, []string, bool) { return nil, nil, true },
		Syncing:   func() bool { return true },
	})
	a.press("ctrl+g", ",", "enter", "ctrl+u", "~/sync")
	_, start := a.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	if !a.syncing {
		t.Fatal("not syncing while starting")
	}
	a.run(a.lock("locked"))
	a.run(start)
	if a.syncing {
		t.Error("still syncing after a start the lock kept from running")
	}
}

// A master password changed on another computer is taken from the sync
// panel: this vault's password, then the new one; the app goes on with
// the vault opened anew, and a wrong one keeps the form.
func TestSync_TakeKeyChange(t *testing.T) {
	old, fresh := newFake(), newFake()
	var asked []string
	var err error
	a := newApp(t, old, Options{
		Settings: func() ([]Setting, error) { return nil, nil },
		SyncState: func() (SyncState, error) {
			return SyncState{Said: "~/sync, master password changed elsewhere", On: true, KeyChanged: true, Lines: []string{"⚠️  the master password was changed on another computer"}}, nil
		},
		TakeKeyChange: func(current, next []byte) (Changed, error) {
			asked = append(asked, string(current)+">"+string(next))
			if err != nil {
				return Changed{}, err
			}
			return Changed{Vault: fresh, Said: []string{"This vault now opens with the new master password, as the other computers' do."}}, nil
		},
		KeyChangeNote: func(Vault) string { return "⚠️ the folder's record may be an older one put back" },
		Sync:          func(Vault, SyncHow) ([]string, []string, bool) { return nil, nil, true },
		Syncing:       func() bool { return true },
	})
	a.press("ctrl+g", ",", "enter")
	if !strings.Contains(a.screen(), "take the new master password") {
		t.Fatalf("the sync panel:\n%s", a.screen())
	}
	a.press("p")
	if a.form == nil || a.form.title != "Take the new master password" || !strings.Contains(a.form.note, "older one put back") {
		t.Fatalf("form %+v", a.form)
	}
	a.press("enter", "enter")
	if a.form == nil || !strings.Contains(a.form.err, "Type this vault's master password") || len(asked) != 0 {
		t.Fatalf("nothing typed: asked %q, form %+v", asked, a.form)
	}
	err = ErrWrongPassword
	a.press("shift+tab", "old-password", "tab", "new-password-1", "enter")
	if a.form == nil || !strings.Contains(a.form.err, "not the current master password") {
		t.Fatalf("a wrong one: asked %q, form %+v", asked, a.form)
	}
	err = nil
	a.press("enter")
	if !slices.Equal(asked, []string{"old-password>new-password-1", "old-password>new-password-1"}) || a.form != nil {
		t.Fatalf("asked %q, form %+v", asked, a.form)
	}
	if !strings.Contains(a.screen(), "now opens with the new master password") || !old.closed || a.v == nil || a.v.v != Vault(fresh) {
		t.Errorf("after: old closed %v\n%s", old.closed, a.screen())
	}
}
