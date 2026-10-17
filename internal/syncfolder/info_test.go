package syncfolder

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bashhack/sesh/internal/kdf"
)

// A folder's info is written readable only by the user and read back the
// same; a folder without one isn't a sync folder.
func TestInfo_WriteRead(t *testing.T) {
	f := New(filepath.Join(t.TempDir(), "sync"))
	if _, err := f.ReadInfo(); !errors.Is(err, ErrNoInfo) {
		t.Fatalf("no info: %v", err)
	}
	info, err := NewInfo(KeyRecord{Salt: []byte("salt-salt-salt-s"), Verify: []byte("verify"), Params: kdf.Minimum()})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.WriteInfo(info); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(filepath.Join(f.Dir(), InfoFile)); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("mode %v, %v", fi.Mode().Perm(), err)
	}
	got, err := f.ReadInfo()
	if err != nil || got.FolderID != info.FolderID || string(got.Key.Salt) != "salt-salt-salt-s" || got.Key.Params != kdf.Minimum() || len(got.FolderID) != 16 {
		t.Errorf("read %+v, %v", got, err)
	}
}

// An info file from a newer sesh, missing its key record, with Argon2id
// settings out of bounds or below the least sesh makes a vault with, with a
// master password change missing a part, or not JSON is refused.
func TestInfo_ReadRefuses(t *testing.T) {
	for name, tc := range map[string]struct{ body, wantSub string }{
		"newer":         {`{"format": 2}`, "newer sesh"},
		"no key":        {`{"format": 1, "folder_id": "ab", "key": {}}`, "missing what a sync folder has"},
		"too much":      {`{"format": 1, "folder_id": "ab", "key": {"salt": "c2FsdA==", "verify": "dg==", "params": {"time": 2, "memory": 4294967295, "threads": 1, "key_len": 32}}}`, "memory"},
		"garbage":       {`not json`, "doesn't read"},
		"too little":    {`{"format": 1, "folder_id": "ab", "key": {"salt": "c2FsdA==", "verify": "dg==", "params": {"time": 1, "memory": 1024, "threads": 1, "key_len": 32}}}`, "below the least"},
		"half recovery": {`{"format": 1, "folder_id": "ab", "key": {"salt": "c2FsdA==", "verify": "dg==", "params": {"time": 2, "memory": 19456, "threads": 1, "key_len": 32}}, "recovery": {"key": "k"}}`, "recovery key record is missing"},
		"half link":     {`{"format": 1, "folder_id": "ab", "key": {"salt": "c2FsdA==", "verify": "dg==", "params": {"time": 2, "memory": 19456, "threads": 1, "key_len": 32}}, "links": [{"from": "a", "to": "b"}]}`, "missing what one has"},
	} {
		f := New(t.TempDir())
		if err := os.WriteFile(filepath.Join(f.Dir(), InfoFile), []byte(tc.body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := f.ReadInfo(); err == nil || !strings.Contains(err.Error(), tc.wantSub) {
			t.Errorf("%s: %v; want an error with %q", name, err, tc.wantSub)
		}
	}
}
