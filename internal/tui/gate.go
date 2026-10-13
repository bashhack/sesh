package tui

import (
	"sync"

	tea "charm.land/bubbletea/v2"
)

// gate is the open vault and the reads running on it. Closing it stops new
// reads and waits for those running, so none is cut off: a copy is never
// left on the clipboard without its clearing, nor a read without its audit
// event. A read that finishes after the gate closed sees it, and wipes
// what it read.
type gate struct {
	v      Vault
	idle   *sync.Cond
	mu     sync.Mutex
	n      int
	closed bool
}

func newGate(v Vault) *gate {
	g := &gate{v: v}
	g.idle = sync.NewCond(&g.mu)
	return g
}

// run is f's message, f given the vault and a way to ask whether the gate
// has closed; nil once it has.
func (g *gate) run(f func(v Vault, closed func() bool) tea.Msg) tea.Msg {
	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		return nil
	}
	g.n++
	g.mu.Unlock()
	defer func() {
		g.mu.Lock()
		g.n--
		g.idle.Broadcast()
		g.mu.Unlock()
	}()
	return f(g.v, g.isClosed)
}

func (g *gate) isClosed() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.closed
}

// close stops new reads, waits for those running, and closes the vault.
func (g *gate) close() {
	g.mu.Lock()
	g.closed = true
	for g.n > 0 {
		g.idle.Wait()
	}
	g.mu.Unlock()
	g.v.Close() //nolint:errcheck,gosec // nothing more to do with the vault
}
