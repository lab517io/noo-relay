// Package limit holds the relay's in-memory abuse limits: a per-key token
// bucket for request rates, and a per-key backoff for repeated failures.
//
// Both are process-local and forget everything on restart, which is fine for
// what they defend against — sustained guessing — and keeps the relay free of
// any store beyond its one SQLite file. Both bound their own memory: a flood
// of distinct keys (spoofed usernames, a sweep of IPv6 addresses) evicts idle
// entries first, and once full, fails open rather than refusing everyone —
// the other limits still stand behind them.
package limit

import (
	"sync"
	"time"
)

// maxKeys bounds each limiter's map. At ~100 bytes an entry, a few MB.
const maxKeys = 100_000

// Rate is a token bucket per key: burst requests at once, refilled at
// perMinute. A zero perMinute disables it.
type Rate struct {
	mu        sync.Mutex
	perSecond float64
	burst     float64
	buckets   map[string]*bucket
}

type bucket struct {
	tokens float64
	last   time.Time
}

func NewRate(perMinute int) *Rate {
	return &Rate{
		perSecond: float64(perMinute) / 60,
		burst:     float64(perMinute),
		buckets:   map[string]*bucket{},
	}
}

// Allow spends one token for key. When none is left it reports how long
// until one will be.
func (r *Rate) Allow(key string, now time.Time) (bool, time.Duration) {
	if r.perSecond == 0 {
		return true, 0
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	b, ok := r.buckets[key]
	if !ok {
		if len(r.buckets) >= maxKeys {
			r.sweep(now)
			if len(r.buckets) >= maxKeys {
				return true, 0
			}
		}
		b = &bucket{tokens: r.burst, last: now}
		r.buckets[key] = b
	}

	b.tokens = min(r.burst, b.tokens+now.Sub(b.last).Seconds()*r.perSecond)
	b.last = now
	if b.tokens >= 1 {
		b.tokens--
		return true, 0
	}
	wait := time.Duration((1 - b.tokens) / r.perSecond * float64(time.Second))
	return false, wait
}

// sweep drops buckets that have refilled completely: forgetting them changes
// nothing, since a new bucket starts full.
func (r *Rate) sweep(now time.Time) {
	for key, b := range r.buckets {
		if b.tokens+now.Sub(b.last).Seconds()*r.perSecond >= r.burst {
			delete(r.buckets, key)
		}
	}
}

// Backoff slows repeated failures for one key: the first free failures cost
// nothing, then each further one doubles the wait before the next attempt,
// from base up to max. A success clears the key; so does forget of quiet.
//
// It is keyed by what an attacker targets (a username) rather than by where
// they are, so spreading guesses over many addresses does not help. The cap
// keeps what it costs the real owner small: at worst a wait of max.
type Backoff struct {
	mu      sync.Mutex
	free    int
	base    time.Duration
	max     time.Duration
	forget  time.Duration
	entries map[string]*failures
}

type failures struct {
	count int
	last  time.Time
	until time.Time
}

func NewBackoff(free int, base, max, forget time.Duration) *Backoff {
	return &Backoff{free: free, base: base, max: max, forget: forget, entries: map[string]*failures{}}
}

// Wait reports how long key must wait before its next attempt; 0 means now.
func (b *Backoff) Wait(key string, now time.Time) time.Duration {
	b.mu.Lock()
	defer b.mu.Unlock()
	f, ok := b.entries[key]
	if !ok {
		return 0
	}
	if now.Sub(f.last) > b.forget {
		delete(b.entries, key)
		return 0
	}
	if now.Before(f.until) {
		return f.until.Sub(now)
	}
	return 0
}

// Fail records a failed attempt for key.
func (b *Backoff) Fail(key string, now time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()
	f, ok := b.entries[key]
	if !ok || now.Sub(f.last) > b.forget {
		if !ok && len(b.entries) >= maxKeys {
			b.sweep(now)
			if len(b.entries) >= maxKeys {
				return
			}
		}
		f = &failures{}
		b.entries[key] = f
	}
	f.count++
	f.last = now
	if over := f.count - b.free; over > 0 {
		delay := b.max
		if over < 32 {
			delay = min(b.max, b.base<<(over-1))
		}
		f.until = now.Add(delay)
	}
}

// Succeed clears key.
func (b *Backoff) Succeed(key string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.entries, key)
}

func (b *Backoff) sweep(now time.Time) {
	for key, f := range b.entries {
		if now.Sub(f.last) > b.forget {
			delete(b.entries, key)
		}
	}
}
