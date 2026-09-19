package sdk

import "testing"

func TestLRUSetAddNewAndDuplicate(t *testing.T) {
	s := newLRUSet(10)
	if !s.Add("a") {
		t.Fatal("first Add(a) should report new")
	}
	if s.Add("a") {
		t.Fatal("second Add(a) should report duplicate")
	}
	if !s.Contains("a") {
		t.Fatal("Contains(a) should be true")
	}
	if s.Contains("b") {
		t.Fatal("Contains(b) should be false")
	}
	if s.Len() != 1 {
		t.Fatalf("Len() = %d, want 1", s.Len())
	}
}

func TestLRUSetEviction(t *testing.T) {
	s := newLRUSet(4)
	s.Add("a")
	s.Add("b")
	s.Add("c")
	s.Add("d")
	// Adding e evicts the least recently used (a).
	s.Add("e")
	if s.Contains("a") {
		t.Fatal("a should have been evicted")
	}
	for _, k := range []string{"b", "c", "d", "e"} {
		if !s.Contains(k) {
			t.Fatalf("%s should still be present", k)
		}
	}
	if s.Len() != 4 {
		t.Fatalf("Len() = %d, want 4", s.Len())
	}
}

func TestLRUSetAddRefreshesRecency(t *testing.T) {
	s := newLRUSet(3)
	s.Add("a")
	s.Add("b")
	s.Add("c")
	// Touch a (re-Add reports duplicate but refreshes recency).
	s.Add("a")
	// Now the LRU order is b, c, a. Adding d evicts b.
	s.Add("d")
	if s.Contains("b") {
		t.Fatal("b should have been evicted (a was refreshed)")
	}
	if !s.Contains("a") || !s.Contains("c") || !s.Contains("d") {
		t.Fatal("a, c, d should be present")
	}
}

func TestLRUSetContainsDoesNotRefresh(t *testing.T) {
	s := newLRUSet(3)
	s.Add("a")
	s.Add("b")
	s.Add("c")
	// Contains(a) must NOT refresh a's recency.
	s.Contains("a")
	// LRU order is still a, b, c. Adding d evicts a.
	s.Add("d")
	if s.Contains("a") {
		t.Fatal("a should have been evicted (Contains must not refresh)")
	}
	if !s.Contains("b") || !s.Contains("c") || !s.Contains("d") {
		t.Fatal("b, c, d should be present")
	}
}

func TestLRUMapSetGetEvict(t *testing.T) {
	m := newLRUMap(3)
	m.set("a", 1)
	m.set("b", 2)
	m.set("c", 3)
	if v, ok := m.get("a"); !ok || v.(int) != 1 {
		t.Fatalf("get(a) = %v, %v", v, ok)
	}
	// Update existing key.
	m.set("a", 10)
	if v, _ := m.get("a"); v.(int) != 10 {
		t.Fatalf("get(a) after update = %v", v)
	}
	// get(a) refreshes recency; order is now b, c, a.
	m.get("a")
	m.set("d", 4) // evicts b
	if _, ok := m.get("b"); ok {
		t.Fatal("b should have been evicted")
	}
	for _, k := range []string{"a", "c", "d"} {
		if _, ok := m.get(k); !ok {
			t.Fatalf("%s should be present", k)
		}
	}
}
