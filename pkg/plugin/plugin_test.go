package plugin

import (
	"testing"

	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/provenance"
)

func TestRegisterAndGet(t *testing.T) {
	p := &dummyPlugin{name: "test"}
	err := Register(p)
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	got := Get("test")
	if got == nil {
		t.Fatal("Get returned nil")
	}
	if got.Name() != "test" {
		t.Errorf("Name = %q", got.Name())
	}
}

func TestRegisterDuplicate(t *testing.T) {
	p := &dummyPlugin{name: "dup"}
	err := Register(p)
	if err != nil {
		t.Fatalf("first register: %v", err)
	}
	err = Register(p)
	if err == nil {
		t.Error("expected error for duplicate registration")
	}
}

func TestList(t *testing.T) {
	names := List()
	if len(names) == 0 {
		t.Log("no plugins registered (expected in isolation)")
	}
}

type dummyPlugin struct {
	name string
}

func (d *dummyPlugin) Name() string { return d.name }
func (d *dummyPlugin) Analyse(snap *provenance.Graph) []*Finding {
	return nil
}
