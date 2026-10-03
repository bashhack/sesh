package touchid

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFile_WriteReadRemove(t *testing.T) {
	dir := t.TempDir()
	f := NewFile("vault-id", []byte("blob"), []byte("pub"), Wrapped{EphemeralPub: []byte("eph"), Ciphertext: []byte("ct")})
	f.BiometryState = []byte("fingerprints")
	if err := f.Write(dir); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dir, FileName))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("mode = %o, want 600", info.Mode().Perm())
	}
	got, err := ReadFile(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got.UnlockID != "vault-id" || string(got.KeyBlob) != "blob" || string(got.Wrapped().Ciphertext) != "ct" || string(got.BiometryState) != "fingerprints" {
		t.Errorf("read back %+v", got)
	}
	if err := Remove(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadFile(dir); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("after Remove: err = %v, want not exist", err)
	}
	if err := Remove(dir); err != nil {
		t.Errorf("removing a missing file: %v", err)
	}
}

func TestReadFile_Rejects(t *testing.T) {
	for name, tt := range map[string]struct{ body, wantSub string }{
		"not JSON":    {"nope", "read "},
		"new version": {`{"version": 2, "unlock_id": "x"}`, "unsupported version 2"},
		"incomplete":  {`{"version": 1, "unlock_id": "x"}`, "incomplete"},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, FileName), []byte(tt.body), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := ReadFile(dir); err == nil || !strings.Contains(err.Error(), tt.wantSub) {
				t.Fatalf("err = %v, want %q", err, tt.wantSub)
			}
		})
	}
}
