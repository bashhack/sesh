package syncfolder

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

// A recovery key record opens as it was sealed, only for its folder and
// key record, and not with another key.
func TestRecovery_SealOpen(t *testing.T) {
	s := newSealer(t)
	r := Recovery{Count: 3, PublicKey: bytes.Repeat([]byte{4}, 65), Computer: "laptop", Made: time.Date(2026, 10, 17, 1, 2, 3, 0, time.UTC)}
	sr, err := SealRecovery(s, "folder-a", "key-1", r)
	if err != nil {
		t.Fatal(err)
	}
	got, err := OpenRecovery(s, "folder-a", sr)
	if err != nil || !got.Same(r) || got.Computer != "laptop" || !got.Made.Equal(r.Made) {
		t.Fatalf("opened %+v, %v", got, err)
	}
	if _, err := OpenRecovery(s, "folder-b", sr); err == nil {
		t.Error("a record opened for another folder")
	}
	moved := *sr
	moved.Key = "key-2"
	if _, err := OpenRecovery(s, "folder-a", &moved); err == nil {
		t.Error("a record opened for another key record")
	}
	if _, err := OpenRecovery(newSealer(t), "folder-a", sr); err == nil {
		t.Error("a record opened with another key")
	}
	long := r
	long.PublicKey = bytes.Repeat([]byte{4}, maxRecoveryKey+1)
	if sr, err = SealRecovery(s, "folder-a", "key-1", long); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenRecovery(s, "folder-a", sr); err == nil || !strings.Contains(err.Error(), "too long") {
		t.Errorf("a key too long: %v", err)
	}
}

func TestRecovery_Same(t *testing.T) {
	a := Recovery{Count: 1, PublicKey: []byte{1}}
	for _, c := range []struct {
		b    Recovery
		same bool
	}{
		{Recovery{Count: 1, PublicKey: []byte{1}, Computer: "other"}, true},
		{Recovery{Count: 2, PublicKey: []byte{1}}, false},
		{Recovery{Count: 1, PublicKey: []byte{2}}, false},
		{Recovery{Count: 1}, false},
	} {
		if a.Same(c.b) != c.same {
			t.Errorf("%+v same as %+v: %v", a, c.b, !c.same)
		}
	}
}
