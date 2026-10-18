package syncfolder

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/bashhack/sesh/internal/totp"
	"github.com/bashhack/sesh/internal/vault"
)

// gcmSealer seals with AES-GCM under one key, as the vault's key would;
// the salt is random and part of the nonce's input only to be checked.
type gcmSealer struct{ key []byte }

func newSealer(t *testing.T) *gcmSealer {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	return &gcmSealer{key: key}
}

func (g *gcmSealer) aead() cipher.AEAD {
	b, err := aes.NewCipher(g.key)
	if err != nil {
		panic(err)
	}
	a, err := cipher.NewGCM(b)
	if err != nil {
		panic(err)
	}
	return a
}

func (g *gcmSealer) EncryptEntry(plaintext, aad []byte) ([]byte, []byte, error) {
	salt := make([]byte, 16)
	nonce := make([]byte, 12)
	if _, err := rand.Read(salt); err != nil {
		return nil, nil, err
	}
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, err
	}
	// The salt is bound in too, as the vault's per-entry key is derived
	// from it.
	return g.aead().Seal(nonce, nonce, plaintext, append(slices.Clone(aad), salt...)), salt, nil
}

func (g *gcmSealer) DecryptEntry(data, salt, aad []byte) ([]byte, error) {
	if len(data) < 12 {
		return nil, errors.New("short")
	}
	return g.aead().Open(nil, data[:12], data[12:], append(slices.Clone(aad), salt...))
}

const (
	uid1  = "00112233445566778899aabbccddeeff"
	uid2  = "ffeeddccbbaa99887766554433221100"
	keyID = "0f0e0d0c0b0a09080706050403020100000102030405060708090a0b0c0d0e0f"
)

func header(t *testing.T, uid string) Header {
	t.Helper()
	h, err := NewHeader(uid, keyID)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func record() *Record {
	at := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	return &Record{
		Created: at, Updated: at.Add(time.Hour),
		Kind: vault.KindTOTP, Service: "GitHub", Username: "alice",
		Computer: "laptop", URL: "https://github.com", Folder: "work/dev",
		Secret: []byte("JBSWY3DPEHPK3PXP"), Notes: []byte("recovery codes in the safe"),
		Fields:   []Field{{Name: "pin", Value: []byte("1234"), Secret: true}, {Name: "team", Value: []byte("core")}},
		Settings: vault.Settings{TOTP: totp.Params{Issuer: "GitHub", Digits: 8}},
		Tags:     []string{"code", "work"},
		History:  []Earlier{{ReplacedAt: at, Computer: "desktop", Secret: []byte("OLDKEYOLDKEYOLD2")}},
		Versions: Versions{"x": 7},
	}
}

// A record sealed opens to the same record, with its uid and key ID in the
// header; nothing of it is readable in the file.
func TestSealOpen(t *testing.T) {
	s := newSealer(t)
	h := header(t, uid1)
	want := record()
	b, err := Seal(s, h, want)
	if err != nil {
		t.Fatal(err)
	}
	for _, plain := range []string{"GitHub", "alice", "JBSWY3DPEHPK3PXP", "recovery", "work/dev", "laptop", "1234"} {
		if bytes.Contains(b, []byte(plain)) {
			t.Errorf("the file holds %q in the clear", plain)
		}
	}
	gotH, got, err := Open(s, b)
	if err != nil {
		t.Fatal(err)
	}
	if gotH.UIDString() != uid1 || gotH.KeyIDString() != keyID {
		t.Errorf("header %s %s", gotH.UIDString(), gotH.KeyIDString())
	}
	if !recordsEqual(got, want) {
		t.Errorf("opened %+v\nwant %+v", got, want)
	}
	// One deleted for good keeps only its version and computer.
	purged := &Record{Purged: time.Date(2026, 10, 17, 0, 0, 0, 0, time.UTC), Computer: "desktop", Versions: Versions{"x": 8}}
	if b, err = Seal(s, h, purged); err != nil {
		t.Fatal(err)
	}
	if _, got, err = Open(s, b); err != nil || !got.Purged.Equal(purged.Purged) || got.Versions["x"] != 8 || got.Service != "" || got.Secret != nil {
		t.Errorf("purged: %+v, %v", got, err)
	}
}

func recordsEqual(a, b *Record) bool {
	return a.Created.Equal(b.Created) && a.Updated.Equal(b.Updated) && a.SetAt.Equal(b.SetAt) && a.Deleted.Equal(b.Deleted) && a.Purged.Equal(b.Purged) &&
		a.Kind == b.Kind && a.Service == b.Service && a.Username == b.Username && a.Computer == b.Computer &&
		a.URL == b.URL && a.Folder == b.Folder && bytes.Equal(a.Secret, b.Secret) && bytes.Equal(a.Notes, b.Notes) &&
		slices.EqualFunc(a.Fields, b.Fields, func(x, y Field) bool {
			return x.Name == y.Name && bytes.Equal(x.Value, y.Value) && x.Secret == y.Secret
		}) &&
		a.Settings == b.Settings && slices.Equal(a.Tags, b.Tags) && maps.Equal(a.Versions, b.Versions) &&
		slices.EqualFunc(a.History, b.History, func(x, y Earlier) bool {
			return x.ReplacedAt.Equal(y.ReplacedAt) && x.SetAt.Equal(y.SetAt) && x.Computer == y.Computer && x.FileName == y.FileName && bytes.Equal(x.Secret, y.Secret)
		})
}

// A file changed anywhere, its record put in another entry's file, or
// sealed with another key doesn't open; neither does one cut short, not a
// sync file, or from a newer sesh.
func TestOpenRefuses(t *testing.T) {
	s := newSealer(t)
	b, err := Seal(s, header(t, uid1), record())
	if err != nil {
		t.Fatal(err)
	}
	other, err := Seal(s, header(t, uid2), record())
	if err != nil {
		t.Fatal(err)
	}
	flip := func(i int) []byte {
		c := slices.Clone(b)
		c[i] ^= 1
		return c
	}
	moved := append(slices.Clone(other[:headerLen]), b[headerLen:]...)
	high := record()
	high.Versions = Versions{"aaaaaaaaaaaaaaaa": MaxCount}
	tooHigh, err := Seal(s, header(t, uid1), high)
	if err != nil {
		t.Fatal(err)
	}
	newer := slices.Clone(b)
	newer[len(magic)] = format + 1
	for name, tc := range map[string]struct {
		sealer  Sealer
		wantSub string
		file    []byte
	}{
		"uid changed":          {file: flip(len(magic) + 1 + 3), wantSub: "message authentication failed"},
		"key ID changed":       {file: flip(len(magic) + 1 + 16 + 5), wantSub: "message authentication failed"},
		"salt changed":         {file: flip(headerLen + 2), wantSub: "message authentication failed"},
		"record changed":       {file: flip(len(b) - 3), wantSub: "message authentication failed"},
		"moved to another":     {file: moved, wantSub: "message authentication failed"},
		"another key":          {file: b, sealer: newSealer(t), wantSub: "message authentication failed"},
		"cut short":            {file: b[:headerLen+4], wantSub: "cut short"},
		"not a sync file":      {file: []byte("hello, this isn't one"), wantSub: "not a sesh sync file"},
		"from a newer sesh":    {file: newer, wantSub: "newer sesh"},
		"count too high":       {file: tooHigh, wantSub: "too high"},
		"format never written": {file: func() []byte { c := slices.Clone(b); c[len(magic)] = 0; return c }(), wantSub: "isn't one sesh writes"},
	} {
		sealer := tc.sealer
		if sealer == nil {
			sealer = s
		}
		if _, r, err := Open(sealer, tc.file); err == nil || r != nil || !strings.Contains(err.Error(), tc.wantSub) {
			t.Errorf("%s: %v, %v; want an error with %q", name, r, err, tc.wantSub)
		}
	}
	if _, err := ParseHeader(newer); !errors.Is(err, ErrNewerFormat) {
		t.Errorf("newer format: %v", err)
	}
}

// NewHeader takes a uid and key ID only in the forms the vault gives them.
func TestNewHeader(t *testing.T) {
	for _, tc := range []struct{ uid, key, wantSub string }{
		{uid1[:30], keyID, "uid"},
		{"zz" + uid1[2:], keyID, "uid"},
		{uid1, keyID[:62], "key ID"},
	} {
		if _, err := NewHeader(tc.uid, tc.key); err == nil || !strings.Contains(err.Error(), tc.wantSub) {
			t.Errorf("NewHeader(%q, %q): %v; want an error with %q", tc.uid, tc.key, err, tc.wantSub)
		}
	}
}

// Write puts an entry's file in entries/, named by its uid, readable only
// by the user, with nothing left over; it refuses a file sealed for
// another entry.
func TestFolderWrite(t *testing.T) {
	s := newSealer(t)
	dir := t.TempDir()
	f := New(filepath.Join(dir, "sync"))
	h := header(t, uid1)
	b, err := Seal(s, h, record())
	if err != nil {
		t.Fatal(err)
	}
	hash, err := f.Write(h, b)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(f.Dir(), "entries", uid1+".sesh")
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, b) || hash != HashOf(b) {
		t.Fatalf("written: %v", err)
	}
	for p, want := range map[string]os.FileMode{path: 0o600, filepath.Dir(path): 0o700} {
		if fi, err := os.Stat(p); err != nil || fi.Mode().Perm() != want {
			t.Errorf("%s: mode %v, %v; want %v", p, fi.Mode().Perm(), err, want)
		}
	}
	des, err := os.ReadDir(filepath.Dir(path))
	if err != nil || len(des) != 1 {
		t.Errorf("entries/ holds %d files, %v; want only the entry's", len(des), err)
	}
	if _, err := f.Write(header(t, uid2), b); err == nil || !strings.Contains(err.Error(), "isn't sealed for it") {
		t.Errorf("a file sealed for another entry: %v", err)
	}
}

// Scan reads entry files and sync tools' copies of them by what's in them,
// counts iCloud's placeholders as not downloaded, skips temporary and
// other files, and lists files that can't be read.
func TestFolderScan(t *testing.T) {
	s := newSealer(t)
	f := New(t.TempDir())
	if c, err := f.Scan(); err != nil || len(c.Files) != 0 {
		t.Fatalf("a new folder: %+v, %v", c, err)
	}
	h := header(t, uid1)
	b, err := Seal(s, h, record())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(h, b); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(f.Dir(), "entries")
	write := func(name string, data []byte) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	copies := []string{
		uid1 + " (MacBook's conflicted copy 2026-10-16).sesh", // Dropbox
		uid1 + ".sync-conflict-20261016-120000-ABCDEFG.sesh",  // Syncthing
		uid1 + " 2.sesh", // iCloud Drive
	}
	for _, c := range copies {
		write(c, b)
	}
	write("."+uid2+".sesh.icloud", []byte("placeholder"))
	write("."+uid2+".sesh.a1b2c3", []byte("temporary"))
	write(".DS_Store", []byte("x"))
	write("notes.txt", []byte("x"))
	write("garbage.sesh", []byte("not one at all"))
	write("short.sesh", b[:headerLen])
	if err := os.Symlink(filepath.Join(dir, uid1+".sesh"), filepath.Join(dir, "link.sesh")); err != nil {
		t.Fatal(err)
	}
	c, err := f.Scan()
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, file := range c.Files {
		if file.UIDString() != uid1 || file.Hash != HashOf(b) {
			t.Errorf("%s: read as %s", file.Path, file.UIDString())
		}
		if got, err := f.Read(&file); err != nil || !bytes.Equal(got, b) {
			t.Errorf("%s: Read: %v", file.Path, err)
		}
		names = append(names, filepath.Base(file.Path))
	}
	slices.Sort(names)
	want := append([]string{uid1 + ".sesh"}, copies...)
	slices.Sort(want)
	if !slices.Equal(names, want) {
		t.Errorf("files %q, want %q", names, want)
	}
	if len(c.NotDownloaded) != 1 || filepath.Base(c.NotDownloaded[0]) != "."+uid2+".sesh.icloud" {
		t.Errorf("not downloaded: %q", c.NotDownloaded)
	}
	why := map[string]string{}
	for _, p := range c.Problems {
		why[filepath.Base(p.Path)] = p.Why
	}
	for name, wantSub := range map[string]string{"garbage.sesh": "not a sesh sync file", "short.sesh": "cut short", "link.sesh": "a link"} {
		if !strings.Contains(why[name], wantSub) {
			t.Errorf("%s: problem %q, want one with %q", name, why[name], wantSub)
		}
	}
	if len(c.Problems) != 3 {
		t.Errorf("problems: %+v", c.Problems)
	}
}

// Remove removes an entry file of the folder's, and nothing else.
func TestFolderRemove(t *testing.T) {
	f := New(t.TempDir())
	dir := filepath.Join(f.Dir(), "entries")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(f.Dir(), "keep.sesh")
	inside := filepath.Join(dir, uid1+" 2.sesh")
	other := filepath.Join(dir, "notes.txt")
	for _, p := range []string{outside, inside, other} {
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, p := range []string{outside, other, filepath.Join(dir, "..", "keep.sesh")} {
		if err := f.Remove(p); err == nil || !strings.Contains(err.Error(), "isn't an entry file") {
			t.Errorf("Remove(%s): %v", p, err)
		}
	}
	if err := f.Remove(inside); err != nil {
		t.Fatal(err)
	}
	for p, want := range map[string]bool{outside: true, other: true, inside: false} {
		if _, err := os.Stat(p); (err == nil) != want {
			t.Errorf("%s: there %v, want %v", p, err == nil, want)
		}
	}
}

// Wipe zeroes every secret a record holds.
func TestRecordWipe(t *testing.T) {
	r := record()
	held := [][]byte{r.Secret, r.Notes, r.Fields[0].Value, r.Fields[1].Value, r.History[0].Secret}
	r.Wipe()
	for _, b := range held {
		if strings.Trim(string(b), "\x00") != "" {
			t.Errorf("%q not wiped", b)
		}
	}
}

// shortSalt seals with a salt of the wrong size.
type shortSalt struct{ *gcmSealer }

func (s shortSalt) EncryptEntry(plaintext, aad []byte) ([]byte, []byte, error) {
	data, salt, err := s.gcmSealer.EncryptEntry(plaintext, aad)
	return data, salt[:8], err
}

// A sealer whose salt isn't the size the header's layout has is refused,
// not written into a file that can't be opened.
func TestSealRefusesASaltOfAnotherSize(t *testing.T) {
	if _, err := Seal(shortSalt{newSealer(t)}, header(t, uid1), record()); err == nil || !strings.Contains(err.Error(), "a salt of 8 bytes, not 16") {
		t.Errorf("Seal: %v", err)
	}
}

// countingSealer is gcmSealer, keeping the size of each piece sealed.
type countingSealer struct {
	*gcmSealer
	sizes []int
}

func (c *countingSealer) EncryptEntry(plaintext, aad []byte) ([]byte, []byte, error) {
	c.sizes = append(c.sizes, len(plaintext))
	return c.gcmSealer.EncryptEntry(plaintext, aad)
}

// A record larger than a piece is sealed in pieces of at most MaxPiece, so
// none is too large for the agent, and opens whole; its pieces can't be
// dropped, reordered, repeated or added to.
func TestSealOpen_Pieces(t *testing.T) {
	c := &countingSealer{gcmSealer: newSealer(t)}
	r := record()
	r.Notes = bytes.Repeat([]byte("n"), 2*MaxPiece+100)
	h := header(t, uid1)
	b, err := Seal(c, h, r)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.sizes) < 3 {
		t.Fatalf("sealed in %d pieces, want at least 3", len(c.sizes))
	}
	for _, n := range c.sizes {
		if n > MaxPiece {
			t.Errorf("a piece of %d bytes, over %d", n, MaxPiece)
		}
	}
	if _, got, err := Open(c, b); err != nil || !bytes.Equal(got.Notes, r.Notes) || got.Service != "GitHub" {
		t.Fatalf("open: %v", err)
	}
	// The pieces, as written.
	var pieces [][]byte
	for rest := b[headerLen:]; len(rest) > 0; {
		n := int(rest[saltLen])<<24 | int(rest[saltLen+1])<<16 | int(rest[saltLen+2])<<8 | int(rest[saltLen+3])
		pieces = append(pieces, rest[:saltLen+4+n])
		rest = rest[saltLen+4+n:]
	}
	join := func(ps ...[]byte) []byte { return append(slices.Clone(b[:headerLen]), slices.Concat(ps...)...) }
	for name, file := range map[string][]byte{
		"the last dropped":   join(pieces[:len(pieces)-1]...),
		"the first dropped":  join(pieces[1:]...),
		"two swapped":        join(append([][]byte{pieces[1], pieces[0]}, pieces[2:]...)...),
		"one repeated":       join(append([][]byte{pieces[0]}, pieces...)...),
		"the last repeated":  join(append(slices.Clone(pieces), pieces[len(pieces)-1])...),
		"bytes added":        append(slices.Clone(b), 0, 0, 0, 0),
		"a piece's length +": func() []byte { c := slices.Clone(b); c[headerLen+saltLen+3]++; return c }(),
	} {
		if _, got, err := Open(c, file); err == nil || got != nil {
			t.Errorf("%s: opened", name)
		}
	}
	// One too large for any sync file is refused before anything is sealed.
	c.sizes = nil
	r.Notes = bytes.Repeat([]byte("n"), MaxFileSize)
	if _, err := Seal(c, h, r); err == nil || !strings.Contains(err.Error(), "over the") || len(c.sizes) != 0 {
		t.Errorf("too large: %v, %d pieces sealed", err, len(c.sizes))
	}
}

// A record with more in it than this sesh knows was written by a newer
// one: it's refused, not opened without what it doesn't know (and written
// back without it).
func TestOpen_UnknownFieldIsNewer(t *testing.T) {
	s := newSealer(t)
	h := header(t, uid1)
	hb := h.bytes()
	plain := []byte(`{"service":"x","computer":"new","versions":{"x":3},"passkeys":[{"id":"p"}]}`)
	sealed, salt, err := s.EncryptEntry(plain, pieceAAD(hb, 0, true))
	if err != nil {
		t.Fatal(err)
	}
	b := append(append(slices.Clone(hb), salt...), byte(len(sealed)>>24), byte(len(sealed)>>16), byte(len(sealed)>>8), byte(len(sealed)))
	b = append(b, sealed...)
	if _, r, err := Open(s, b); !errors.Is(err, ErrNewerFormat) || r != nil {
		t.Errorf("Open: %v, %v; want ErrNewerFormat", r, err)
	}
}

// A file whose data is still in the cloud is counted as not downloaded,
// and not opened, which would wait on the download.
func TestFolderScan_NotDownloaded(t *testing.T) {
	s := newSealer(t)
	f := New(t.TempDir())
	for _, uid := range []string{uid1, uid2} {
		b, err := Seal(s, header(t, uid), record())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.Write(header(t, uid), b); err != nil {
			t.Fatal(err)
		}
	}
	was := isDataless
	defer func() { isDataless = was }()
	isDataless = func(fi os.FileInfo) bool { return strings.HasPrefix(fi.Name(), uid2) }
	c, err := f.Scan()
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Files) != 1 || c.Files[0].UIDString() != uid1 || len(c.NotDownloaded) != 1 || !strings.HasPrefix(filepath.Base(c.NotDownloaded[0]), uid2) || len(c.Problems) != 0 {
		t.Errorf("scan: %+v", c)
	}
}

// A pipe in the folder is listed as a problem at once, not waited on; a
// file changed after the scan isn't read as the one scanned.
func TestFolderScan_PipeAndChanged(t *testing.T) {
	s := newSealer(t)
	f := New(t.TempDir())
	h := header(t, uid1)
	b, err := Seal(s, h, record())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(h, b); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(f.Dir(), "entries")
	if err := syscall.Mkfifo(filepath.Join(dir, "pipe.sesh"), 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan *Contents, 1)
	go func() {
		c, err := f.Scan()
		if err != nil {
			t.Error(err)
		}
		done <- c
	}()
	var c *Contents
	select {
	case c = <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Scan waited on a pipe")
	}
	if len(c.Problems) != 1 || !strings.Contains(c.Problems[0].Why, "not a regular file") || len(c.Files) != 1 {
		t.Fatalf("scan: %+v", c)
	}
	other, err := Seal(s, h, record())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(h, other); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Read(&c.Files[0]); err == nil || !strings.Contains(err.Error(), "changed since the folder was read") {
		t.Errorf("Read after a change: %v", err)
	}
}

// An entries/ that's a link isn't written, read or removed through; one
// others can read is made the user's alone.
func TestFolder_EntriesFolder(t *testing.T) {
	s := newSealer(t)
	h := header(t, uid1)
	b, err := Seal(s, h, record())
	if err != nil {
		t.Fatal(err)
	}
	elsewhere := t.TempDir()
	victim := filepath.Join(elsewhere, "keep.sesh")
	if err := os.WriteFile(victim, b, 0o600); err != nil {
		t.Fatal(err)
	}
	f := New(t.TempDir())
	if err := os.Symlink(elsewhere, filepath.Join(f.Dir(), "entries")); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(h, b); err == nil || !strings.Contains(err.Error(), "isn't a folder") {
		t.Errorf("Write through a link: %v", err)
	}
	if _, err := f.Scan(); err == nil || !strings.Contains(err.Error(), "isn't a folder") {
		t.Errorf("Scan through a link: %v", err)
	}
	if err := f.Remove(filepath.Join(f.Dir(), "entries", "keep.sesh")); err == nil {
		t.Error("Remove through a link")
	}
	if _, err := os.Stat(victim); err != nil {
		t.Errorf("the file the link leads to: %v", err)
	}
	if _, err := os.Stat(filepath.Join(elsewhere, uid1+".sesh")); err == nil {
		t.Error("written through the link")
	}
	loose := New(t.TempDir())
	if err := os.Mkdir(filepath.Join(loose.Dir(), "entries"), 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(loose.Dir(), "entries"), 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := loose.Write(h, b); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(filepath.Join(loose.Dir(), "entries")); err != nil || fi.Mode().Perm() != 0o700 {
		t.Errorf("entries/ mode %v, %v; want 0700", fi.Mode().Perm(), err)
	}
}

// sealPieces is a file of the pieces given, each sealed with its place and
// whether it's marked last, as Seal would seal them.
func sealPieces(t *testing.T, s Sealer, h Header, pieces []string, last []bool) [][]byte {
	t.Helper()
	var out [][]byte
	for i, p := range pieces {
		sealed, salt, err := s.EncryptEntry([]byte(p), pieceAAD(h.bytes(), uint32(i), last[i])) //nolint:gosec // a few pieces
		if err != nil {
			t.Fatal(err)
		}
		n := len(sealed)
		out = append(out, append(append(slices.Clone(salt), byte(n>>24), byte(n>>16), byte(n>>8), byte(n)), sealed...))
	}
	return out
}

// Pieces whose record still reads when moved or dropped are refused all
// the same: by their places, and by which is the last.
func TestOpen_PiecesBound(t *testing.T) {
	s := newSealer(t)
	h := header(t, uid1)
	file := func(ps ...[]byte) []byte { return append(h.bytes(), slices.Concat(ps...)...) }
	p := sealPieces(t, s, h, []string{`{"service":"`, `ab`, `ba`, `","versions":{"x":1}}`}, []bool{false, false, false, true})
	if _, r, err := Open(s, file(p...)); err != nil || r.Service != "abba" {
		t.Fatalf("as sealed: %+v, %v", r, err)
	}
	if _, r, err := Open(s, file(p[0], p[2], p[1], p[3])); err == nil {
		t.Errorf("two pieces swapped: opened, service %q", r.Service)
	}
	// A record whole in its first piece, with a last piece after.
	q := sealPieces(t, s, h, []string{`{"service":"x","versions":{"x":1}}`, ` `}, []bool{false, true})
	if _, _, err := Open(s, file(q...)); err != nil {
		t.Fatalf("as sealed: %v", err)
	}
	if _, r, err := Open(s, file(q[0])); err == nil {
		t.Errorf("the last dropped: opened, service %q", r.Service)
	}
}
