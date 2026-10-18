package vaultsync

import (
	"sync/atomic"
	"testing"

	"github.com/bashhack/sesh/internal/database"
	"github.com/bashhack/sesh/internal/kdf"
)

// countingOracle counts the entries opened through it.
type countingOracle struct {
	database.CryptoOracle
	opened atomic.Int64
}

func (c *countingOracle) DecryptEntry(data, salt, aad []byte) ([]byte, error) {
	c.opened.Add(1)
	return c.CryptoOracle.DecryptEntry(data, salt, aad)
}

// A sync with nothing new opens no entry: only one changed is opened.
func TestSync_NothingNewOpensNothing(t *testing.T) {
	t.Parallel()
	laptop, desktop, f := twoComputers(t)
	for _, s := range []string{"a", "b", "c", "d"} {
		laptop.put(s, "pw-"+s)
	}
	laptop.sync(f)
	desktop.sync(f)
	path := desktop.store.Path()
	if err := desktop.store.Close(); err != nil {
		t.Fatal(err)
	}
	prompt := func(string) ([]byte, error) { return []byte("correct horse battery"), nil }
	counted := &countingOracle{CryptoOracle: database.NewKeySourceOracle(database.NewMasterPasswordSource(path, prompt, database.WithKDFParams(kdf.Minimum())))}
	s, err := database.Open(path, counted)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() }) //nolint:errcheck // test cleanup
	again := &computer{t: t, store: s, name: desktop.name}
	if sum := again.sync(f); !sum.Nothing() {
		t.Fatalf("a second sync: %+v", sum)
	}
	if n := counted.opened.Load(); n != 0 {
		t.Errorf("a sync with nothing new opened %d entries", n)
	}
	laptop.put("b", "pw-b2")
	laptop.sync(f)
	again.sync(f)
	if n := counted.opened.Load(); n == 0 || n > 4 {
		t.Errorf("a sync taking one change opened %d entries' worth", n)
	}
}
