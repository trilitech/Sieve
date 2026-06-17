// Package ratelimit — see doc.go for the contract.
package ratelimit

import (
	"container/list"
	"sync"
	"time"
)

// Limiter is a per-key token-bucket limiter with an LRU bound on the
// number of distinct keys tracked. Goroutine-safe.
type Limiter struct {
	capacity int
	refill   time.Duration
	maxKeys  int

	now func() time.Time // testable clock

	mu      sync.Mutex
	buckets map[string]*list.Element // key → element in lru
	lru     *list.List               // front = most recent
}

type bucket struct {
	key     string
	tokens  float64
	updated time.Time
}

// NewLimiter constructs a per-key token-bucket limiter.
// - capacity: bucket size (max consecutive failures before refusal).
// Zero or negative is replaced with 10.
// - refill: one token added every `refill` duration. Zero or negative
// is replaced with 6 seconds (matches the documented 10/minute default).
// - maxKeys: LRU bound on tracked keys. Zero is replaced with 10000.
func NewLimiter(capacity int, refill time.Duration, maxKeys int) *Limiter {
	if capacity <= 0 {
		capacity = 10
	}
	if refill <= 0 {
		refill = 6 * time.Second
	}
	if maxKeys <= 0 {
		maxKeys = 10000
	}
	return &Limiter{
		capacity: capacity,
		refill:   refill,
		maxKeys:  maxKeys,
		now:      time.Now,
		buckets:  make(map[string]*list.Element),
		lru:      list.New(),
	}
}

// Allow consumes one token from the key's bucket. Returns (true, 0) if a
// token was available; (false, retry-after) if the bucket was empty.
func (l *Limiter) Allow(key string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()

	b := l.touch(key)
	b.refill(l.now(), l.refill, l.capacity)
	if b.tokens < 1 {
		// Time until the next whole token.
		need := 1.0 - b.tokens
		retryAfter := time.Duration(need * float64(l.refill))
		if retryAfter < time.Second {
			retryAfter = time.Second
		}
		return false, retryAfter
	}
	b.tokens--
	return true, 0
}

// Refund returns one token to the key's bucket. Used after a successful
// authentication so legitimate high-throughput clients are not penalised
// for an occasional auth failure.
func (l *Limiter) Refund(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if elem, ok := l.buckets[key]; ok {
		b := elem.Value.(*bucket)
		b.refill(l.now(), l.refill, l.capacity)
		if b.tokens < float64(l.capacity) {
			b.tokens++
		}
	}
}

// Count returns the current token level for the key (testing + metrics).
// Returns capacity for unknown keys (a fresh bucket).
func (l *Limiter) Count(key string) float64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	if elem, ok := l.buckets[key]; ok {
		b := elem.Value.(*bucket)
		b.refill(l.now(), l.refill, l.capacity)
		return b.tokens
	}
	return float64(l.capacity)
}

// touch returns the bucket for key, creating it (and evicting the LRU
// tail if maxKeys is hit) if it doesn't exist. Moves the bucket to the
// front of the LRU list. Caller MUST hold l.mu.
func (l *Limiter) touch(key string) *bucket {
	if elem, ok := l.buckets[key]; ok {
		l.lru.MoveToFront(elem)
		return elem.Value.(*bucket)
	}
	if l.lru.Len() >= l.maxKeys {
		oldest := l.lru.Back()
		if oldest != nil {
			ob := oldest.Value.(*bucket)
			delete(l.buckets, ob.key)
			l.lru.Remove(oldest)
		}
	}
	b := &bucket{
		key:     key,
		tokens:  float64(l.capacity),
		updated: l.now(),
	}
	elem := l.lru.PushFront(b)
	l.buckets[key] = elem
	return b
}

// refill advances the bucket's token level to reflect elapsed time.
func (b *bucket) refill(now time.Time, interval time.Duration, capacity int) {
	if now.Before(b.updated) {
		b.updated = now
		return
	}
	elapsed := now.Sub(b.updated)
	tokens := b.tokens + float64(elapsed)/float64(interval)
	if tokens > float64(capacity) {
		tokens = float64(capacity)
	}
	b.tokens = tokens
	b.updated = now
}
