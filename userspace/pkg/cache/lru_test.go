package cache

import (
	"testing"
)

func TestNewCache(t *testing.T) {
	evicted := make(map[string]bool)
	c, err := New(3, func(id string) error {
		evicted[id] = true
		return nil
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if c.Len() != 0 {
		t.Errorf("expected empty cache, got %d", c.Len())
	}
}

func TestAddAndEvict(t *testing.T) {
	var evicted []string
	c, _ := New(3, func(id string) error {
		evicted = append(evicted, id)
		return nil
	})

	c.Add("a")
	c.Add("b")
	c.Add("c")
	if c.Len() != 3 {
		t.Errorf("len = %d, want 3", c.Len())
	}

	// Adding a 4th should evict "a" (LRU)
	c.Add("d")
	if len(evicted) != 1 || evicted[0] != "a" {
		t.Errorf("expected 'a' evicted, got %v", evicted)
	}

	if found, _ := c.Get("a"); found {
		t.Error("'a' should have been evicted")
	}
	if found, _ := c.Get("d"); !found {
		t.Error("'d' should be in cache")
	}
}

func TestGetRefreshesLRU(t *testing.T) {
	var evicted []string
	c, _ := New(3, func(id string) error {
		evicted = append(evicted, id)
		return nil
	})

	c.Add("a")
	c.Add("b")
	c.Add("c")
	c.Get("a") // refresh 'a'

	// Now add 'd' — should evict 'b' (not 'a' since 'a' was touched)
	c.Add("d")
	if len(evicted) != 1 || evicted[0] != "b" {
		t.Errorf("expected 'b' evicted after refreshing 'a', got %v", evicted)
	}
}

func TestRemove(t *testing.T) {
	var evicted []string
	c, _ := New(3, func(id string) error {
		evicted = append(evicted, id)
		return nil
	})

	c.Add("a")
	c.Add("b")
	c.Remove("a")

	if found, _ := c.Get("a"); found {
		t.Error("'a' should be removed")
	}
	if len(evicted) != 0 {
		t.Error("Remove should not call evict callback")
	}
}

func TestEvictColdSync(t *testing.T) {
	var evicted []string
	c, _ := New(10, func(id string) error {
		evicted = append(evicted, id)
		return nil
	})

	for _, id := range []string{"a", "b", "c", "d", "e"} {
		c.Add(id)
	}

	n, err := c.EvictColdSync(3)
	if err != nil {
		t.Fatalf("EvictColdSync: %v", err)
	}
	if n != 3 {
		t.Errorf("evicted %d, want 3", n)
	}
	if c.Len() != 2 {
		t.Errorf("cache len = %d, want 2", c.Len())
	}

	// The remaining 2 should be the most recently added (d, e)
	for _, id := range []string{"a", "b", "c"} {
		if found, _ := c.Get(id); found {
			t.Errorf("%s should have been evicted", id)
		}
	}
}

func TestContains(t *testing.T) {
	c, _ := New(3, func(id string) error { return nil })
	c.Add("a")
	if !c.Contains("a") {
		t.Error("Contains('a') should be true")
	}
	if c.Contains("z") {
		t.Error("Contains('z') should be false")
	}
}

func TestStats(t *testing.T) {
	c, _ := New(3, func(id string) error { return nil })
	c.Add("a")
	c.Get("a")
	c.Get("b") // miss
	stats := c.Stats()
	if stats["hits"].(int64) != 1 {
		t.Errorf("hits = %d, want 1", stats["hits"])
	}
	if stats["misses"].(int64) != 1 {
		t.Errorf("misses = %d, want 1", stats["misses"])
	}
	if stats["size"].(int) != 1 {
		t.Errorf("size = %d, want 1", stats["size"])
	}
}

func TestConcurrency(t *testing.T) {
	c, _ := New(100, func(id string) error { return nil })
	done := make(chan bool)

	go func() {
		for i := 0; i < 100; i++ {
			c.Add(string(rune('a' + (i % 26))))
		}
		done <- true
	}()
	go func() {
		for i := 0; i < 100; i++ {
			c.Get(string(rune('a' + (i % 26))))
		}
		done <- true
	}()
	go func() {
		for i := 0; i < 100; i++ {
			c.Stats()
		}
		done <- true
	}()

	<-done
	<-done
	<-done
	// Should not deadlock or race
}
