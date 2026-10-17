package agent

import (
	"bytes"
	"testing"
	"time"

	"github.com/bashhack/sesh/internal/syncfolder"
)

// A sync file of an entry far larger than one request carries (a file
// entry at its largest, with its history) seals and opens through the
// agent, piece by piece, on one connection.
func TestOracle_SealsLargeSyncFiles(t *testing.T) {
	sockPath := tempSocketPath(t)
	serve(t, sockPath)
	conn, id := unlockClient(t, sockPath)
	defer mustClose(t, conn)
	o := NewOracle(conn, id)
	h, err := syncfolder.NewHeader("00112233445566778899aabbccddeeff", id)
	if err != nil {
		t.Fatal(err)
	}
	r := &syncfolder.Record{Service: "big", Secret: bytes.Repeat([]byte{1}, 1<<20), Versions: syncfolder.Versions{"x": 1}}
	for range 10 {
		r.History = append(r.History, syncfolder.Earlier{ReplacedAt: time.Now(), Secret: bytes.Repeat([]byte{2}, 1<<20)})
	}
	b, err := syncfolder.Seal(o, h, r)
	if err != nil {
		t.Fatal(err)
	}
	_, got, err := syncfolder.Open(o, b)
	if err != nil || len(got.History) != 10 || !bytes.Equal(got.Secret, r.Secret) {
		t.Fatalf("open: %v", err)
	}
	// The connection still serves after.
	if _, _, err := syncfolder.Open(o, b); err != nil {
		t.Errorf("open again: %v", err)
	}
}
