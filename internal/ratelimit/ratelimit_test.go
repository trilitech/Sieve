package ratelimit

import (
	"testing"
	"time"
)

// Per-key constant-refill token bucket. Defaults: capacity 10, refill
// 6s per token, LRU bound 10000 keys.

// fakeClock returns a deterministic time source that tests can advance.
type fakeClock struct{ now time.Time }

func (c *fakeClock) advance(d time.Duration) { c.now = c.now.Add(d) }

func newTestLimiter(cap int, refill time.Duration) (*Limiter, *fakeClock) {
	clk := &fakeClock{now: time.Unix(1_700_000_000, 0)}
	l := NewLimiter(cap, refill, 100)
	l.now = func() time.Time { return clk.now }
	return l, clk
}

func TestAllowConsumesUntilEmpty(t *testing.T) {
	l, _ := newTestLimiter(3, time.Second)
	for i := 0; i < 3; i++ {
		ok, _ := l.Allow("k")
		if !ok {
			t.Fatalf("Allow %d: want true", i)
		}
	}
	ok, retry := l.Allow("k")
	if ok {
		t.Fatal("4th Allow should be denied")
	}
	if retry <= 0 {
		t.Errorf("retry-after should be positive, got %v", retry)
	}
}

func TestRefundReturnsToken(t *testing.T) {
	l, _ := newTestLimiter(2, time.Second)
	l.Allow("k")
	l.Allow("k")
	if ok, _ := l.Allow("k"); ok {
		t.Fatal("third Allow should be denied")
	}
	l.Refund("k")
	if ok, _ := l.Allow("k"); !ok {
		t.Fatal("Allow after Refund should succeed")
	}
}

func TestRefundDoesNotExceedCapacity(t *testing.T) {
	l, _ := newTestLimiter(2, time.Second)
	// Bucket starts full. Spurious refunds shouldn't push it past capacity.
	l.Refund("k")
	l.Refund("k")
	if got := l.Count("k"); got > 2 {
		t.Errorf("bucket exceeded capacity: %v", got)
	}
}

func TestRefillRecoversOverTime(t *testing.T) {
	l, clk := newTestLimiter(2, time.Second)
	l.Allow("k")
	l.Allow("k")
	if ok, _ := l.Allow("k"); ok {
		t.Fatal("Allow at empty should be denied")
	}
	clk.advance(time.Second + 100*time.Millisecond) // > 1 refill interval
	if ok, _ := l.Allow("k"); !ok {
		t.Errorf("Allow after refill should succeed (count=%v)", l.Count("k"))
	}
}

func TestLRUEviction(t *testing.T) {
	l := NewLimiter(2, time.Second, 3) // bound = 3 keys
	l.Allow("a")
	l.Allow("b")
	l.Allow("c")
	// All three are tracked; "a" is the oldest. Inserting "d" should
	// evict "a" — which then gets a fresh (full) bucket next time.
	l.Allow("a")
	l.Allow("a") // consume both tokens
	if ok, _ := l.Allow("a"); ok {
		t.Fatal("a should be empty")
	}
	l.Allow("b")
	l.Allow("c")
	l.Allow("d") // forces an eviction
	// After eviction, the oldest key ("a") should have a fresh bucket
	// when next touched.
	if got := l.Count("a"); got != 2 {
		t.Errorf("after eviction, a's count = %v, want 2 (fresh)", got)
	}
}

func TestKeysAreIndependent(t *testing.T) {
	l, _ := newTestLimiter(2, time.Second)
	l.Allow("a")
	l.Allow("a")
	if ok, _ := l.Allow("a"); ok {
		t.Fatal("a exhausted but Allow succeeded")
	}
	if ok, _ := l.Allow("b"); !ok {
		t.Fatal("b should be untouched by a's drain")
	}
}

func TestDefaultsApplied(t *testing.T) {
	l := NewLimiter(0, 0, 0)
	if l.capacity != 10 {
		t.Errorf("capacity default = %d, want 10", l.capacity)
	}
	if l.refill != 6*time.Second {
		t.Errorf("refill default = %v, want 6s", l.refill)
	}
	if l.maxKeys != 10000 {
		t.Errorf("maxKeys default = %d, want 10000", l.maxKeys)
	}
}
