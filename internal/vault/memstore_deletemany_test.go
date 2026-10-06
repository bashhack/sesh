package vault

import (
	"errors"
	"testing"
)

func TestMemStore_DeleteMany(t *testing.T) {
	m := NewMemStore()
	a, b := Key{Kind: KindPassword, Service: "a"}, Key{Kind: KindPassword, Service: "b"}
	for _, k := range []Key{a, b} {
		if err := m.Put(k, []byte("v")); err != nil {
			t.Fatal(err)
		}
	}
	if err := m.DeleteMany([]Key{a, {Kind: KindPassword, Service: "missing"}}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
	if _, err := m.Lookup(a); err != nil {
		t.Errorf("deleted although another was missing: %v", err)
	}
	if err := m.DeleteMany([]Key{a, b}); err != nil {
		t.Fatal(err)
	}
	if es, err := m.List(Filter{}); err != nil || len(es) != 0 {
		t.Errorf("left %v, %v", es, err)
	}
}
