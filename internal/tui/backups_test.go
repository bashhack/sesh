package tui

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
)

// backupsApp is the app with fake backups, recording what's asked of them; restoring fails with restoreErr.
func backupsApp(t *testing.T, restoreErr error) (*app, *[]string) {
	t.Helper()
	list := []Backup{
		{Made: time.Date(2026, 10, 14, 9, 0, 0, 0, time.UTC), Name: "passwords-3f9c2a1b-2026-10-14T090000Z.db", Path: "/b/new.db", Size: "1.2 MB"},
		{Made: time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC), Name: "passwords-77aa0000-2026-10-01T090000Z.db", Path: "/b/other.db", Size: "1.0 MB", Other: true},
	}
	var asked []string
	files := map[string]bool{}
	a := newApp(t, newFake(), Options{
		Backups: func() (Backups, error) { return Backups{Dir: "~/b", List: slices.Clone(list)}, nil },
		BackUp: func(to string, replace bool) (string, error) {
			asked = append(asked, "backup "+to+map[bool]string{true: " replace", false: ""}[replace])
			if to != "" && files[to] && !replace {
				return "", Exists(to + " already exists.")
			}
			files[to] = true
			if to == "" {
				list = append([]Backup{{Made: time.Date(2026, 10, 15, 9, 0, 0, 0, time.UTC), Name: "passwords-3f9c2a1b-2026-10-15T090000Z.db", Path: "/b/newest.db", Size: "1.3 MB"}}, list...)
			}
			return "Backed up the vault.", nil
		},
		DeleteBackup: func(path string) (string, error) {
			asked = append(asked, "delete "+path)
			list = slices.DeleteFunc(list, func(b Backup) bool { return b.Path == path })
			return "Deleted the backup.", nil
		},
		RenewBackups: func() (string, error) {
			asked = append(asked, "renew")
			return "Deleted 1 backup; made a fresh one.", nil
		},
		PlanRestore: func(path string) (string, error) {
			asked = append(asked, "plan "+path)
			return "Restore the vault from " + path + ", made 2026-10-14 09:00 (3 entries)?", nil
		},
		Restore: func(path string) (string, error) {
			asked = append(asked, "restore "+path)
			if restoreErr != nil {
				return "", restoreErr
			}
			return "Restored the vault from " + path + ".", nil
		},
	})
	return a, &asked
}

// Ctrl-K b lists the backups newest first, another vault's marked; n backs up now and the list grows.
func TestBackupsList(t *testing.T) {
	a, asked := backupsApp(t, nil)
	a.press("ctrl+k", "b")
	s := a.screen()
	if !strings.Contains(s, "Backups in ~/b") || !strings.Contains(s, "2026-10-14") || !strings.Contains(s, "(another vault)") {
		t.Fatalf("the panel:\n%s", s)
	}
	a.press("n")
	if s := a.screen(); !slices.Equal(*asked, []string{"backup "}) || !strings.Contains(s, "passwords-3f9c2a1b-2026-10-15") || !strings.Contains(s, "Backed up the vault.") {
		t.Errorf("asked %q\n%s", *asked, s)
	}
}

// f backs up to a file, asking before replacing one there.
func TestBackupsToFile(t *testing.T) {
	a, asked := backupsApp(t, nil)
	a.press("ctrl+k", "b", "f", "~/copy.db", "enter")
	a.press("f", "~/copy.db", "enter")
	if a.ov == nil || a.ov.kind != panelConfirm || !strings.Contains(a.ov.question, "~/copy.db already exists. Replace it") {
		t.Fatalf("asked %q, panel %+v", *asked, a.ov)
	}
	a.press("wait", "y")
	if !slices.Equal(*asked, []string{"backup ~/copy.db", "backup ~/copy.db", "backup ~/copy.db replace"}) || a.ov == nil || a.ov.kind != panelBackups {
		t.Errorf("asked %q, panel %+v", *asked, a.ov)
	}
}

// x deletes the selected backup after asking, saying when it's another vault's; a deletes this vault's and makes a fresh one.
func TestBackupsDelete(t *testing.T) {
	a, asked := backupsApp(t, nil)
	a.press("ctrl+k", "b", "down", "x")
	if a.ov == nil || a.ov.kind != panelConfirm || !a.ov.danger || !strings.Contains(a.ov.question, "It's another vault's.") {
		t.Fatalf("panel %+v", a.ov)
	}
	a.press("n", "x", "wait", "y")
	if !slices.Equal(*asked, []string{"delete /b/other.db"}) || strings.Contains(a.screen(), "(another vault)") {
		t.Fatalf("asked %q\n%s", *asked, a.screen())
	}
	a.press("a", "wait", "y")
	if !slices.Equal(*asked, []string{"delete /b/other.db", "renew"}) {
		t.Errorf("asked %q", *asked)
	}
}

// Enter asks with what sesh restore says, then restores, reading nothing meanwhile, and locks.
func TestBackupsRestore(t *testing.T) {
	a, asked := backupsApp(t, nil)
	f := a.v.v.(*fakeVault)
	a.press("ctrl+k", "b", "enter")
	if a.ov == nil || a.ov.kind != panelConfirm || !a.ov.danger || !strings.Contains(a.ov.question, "Restore the vault from /b/new.db") || !strings.Contains(a.ov.question, "sesh ui locks after") {
		t.Fatalf("asked %q, panel %+v", *asked, a.ov)
	}
	a.now = a.now.Add(time.Second)
	_, restore := a.Update(tea.KeyPressMsg{Code: 'y', Text: "y"})
	f.err, f.checkErr = Locked("the key changed"), Locked("the key changed")
	a.tick(2 * time.Second)
	a.press("esc", "x")
	if a.v == nil || !strings.Contains(a.screen(), "Restoring the vault…") {
		t.Fatalf("meanwhile: locked %v\n%s", a.v == nil, a.screen())
	}
	a.run(restore)
	if a.v != nil || !strings.Contains(a.lockedWhy, "Restored the vault from /b/new.db. Unlock it with the master password the backup had.") {
		t.Errorf("after: locked %v, %q", a.v == nil, a.lockedWhy)
	}
	if !slices.Equal(*asked, []string{"plan /b/new.db", "restore /b/new.db"}) {
		t.Errorf("asked %q", *asked)
	}
}

// A restore that fails says why, and the app goes on; Ctrl-C during one quits once it's done.
func TestBackupsRestoreFails(t *testing.T) {
	a, _ := backupsApp(t, errors.New("the backup is damaged"))
	a.press("ctrl+k", "b", "enter", "wait", "y")
	if a.v == nil || a.ov == nil || a.ov.kind != panelBackups || !strings.Contains(a.ov.err, "Not restored: the backup is damaged") {
		t.Fatalf("locked %v, panel %+v", a.v == nil, a.ov)
	}
	b, _ := backupsApp(t, nil)
	b.press("ctrl+k", "b", "enter")
	b.now = b.now.Add(time.Second)
	_, restore := b.Update(tea.KeyPressMsg{Code: 'y', Text: "y"})
	b.press("ctrl+c")
	if b.quit || !strings.Contains(b.screen(), "Quitting once the vault is restored") {
		t.Fatalf("quit %v\n%s", b.quit, b.screen())
	}
	b.run(restore)
	if !b.quit || b.Afterword() != "Restored the vault from /b/new.db." {
		t.Errorf("quit %v, said after %q", b.quit, b.Afterword())
	}
}

// With none, the panel says how to make one; it fits the smallest window.
func TestBackupsEmpty(t *testing.T) {
	a := newApp(t, newFake(), Options{Backups: func() (Backups, error) { return Backups{Dir: "~/b"}, nil }})
	a.Update(tea.WindowSizeMsg{Width: minWidth, Height: minHeight})
	a.press("ctrl+k", "b")
	if s := a.screen(); !strings.Contains(s, "No backups yet") || strings.Count(s, "\n")+1 > minHeight {
		t.Errorf("empty:\n%s", s)
	}
}

// The panel, its hint and the selected backup's detail fit every window.
func TestBackupsFits(t *testing.T) {
	for w := minWidth; w <= 100; w += 4 {
		for h := minHeight; h <= 30; h += 3 {
			a, _ := backupsApp(t, nil)
			a.Update(tea.WindowSizeMsg{Width: w, Height: h})
			a.press("ctrl+k", "b")
			s := a.screen()
			hint := false
			for l := range strings.SplitSeq(s, "\n") {
				hint = hint || strings.Contains(l, "restore") && strings.Contains(l, "esc")
			}
			if strings.Count(s, "\n")+1 > h || !hint {
				t.Fatalf("at %dx%d, the hint on one line:\n%s", w, h, s)
			}
		}
	}
}

// A file to back up to is asked for; none typed, the form says so.
func TestBackupsToNothing(t *testing.T) {
	a, asked := backupsApp(t, nil)
	a.press("ctrl+k", "b", "f", "enter")
	if a.form == nil || a.form.err != "Type where to put it." || len(*asked) != 0 {
		t.Errorf("asked %q, form %+v", *asked, a.form)
	}
}

// A restore that fails reads the entries and the backups again, which the restore had let go.
func TestBackupsRestoreFailsReads(t *testing.T) {
	a, _ := backupsApp(t, errors.New("the backup is damaged"))
	f := a.v.v.(*fakeVault)
	reads := 0
	list := a.opts.Backups
	a.opts.Backups = func() (Backups, error) { reads++; return list() }
	a.press("ctrl+k", "b")
	searched, read := f.searched, reads
	a.press("enter", "wait", "y")
	if f.searched == searched || reads == read {
		t.Errorf("searched %d → %d, backups read %d → %d", searched, f.searched, read, reads)
	}
}

// A restore's question that comes back after the app locked and unlocked isn't asked.
func TestBackupsPlanAcrossLock(t *testing.T) {
	a, _ := backupsApp(t, nil)
	a.press("ctrl+k", "b")
	_, plan := a.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	a.run(a.lock("You locked it."))
	a.run(func() tea.Msg { return unlockedMsg{v: newFake()} })
	a.press("ctrl+k", "b")
	a.run(plan)
	if a.ov == nil || a.ov.kind != panelBackups {
		t.Errorf("panel %+v", a.ov)
	}
}
