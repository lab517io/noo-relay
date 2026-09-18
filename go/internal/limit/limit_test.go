package limit

import (
	"fmt"
	"testing"
	"time"
)

func TestRateAllowsBurstThenRefills(t *testing.T) {
	r := NewRate(6) // 6 a minute: one every 10 s
	now := time.Unix(0, 0)

	for i := 0; i < 6; i++ {
		if ok, _ := r.Allow("ip", now); !ok {
			t.Fatalf("request %d of the burst refused", i+1)
		}
	}
	ok, wait := r.Allow("ip", now)
	if ok || wait != 10*time.Second {
		t.Fatalf("after the burst: ok=%v wait=%v, want refused with 10s", ok, wait)
	}
	if ok, _ := r.Allow("other-ip", now); !ok {
		t.Fatal("one key's exhaustion leaked into another's")
	}
	if ok, _ := r.Allow("ip", now.Add(10*time.Second)); !ok {
		t.Fatal("no token after the refill interval")
	}
}

func TestRateZeroDisables(t *testing.T) {
	r := NewRate(0)
	for i := 0; i < 1000; i++ {
		if ok, _ := r.Allow("ip", time.Unix(0, 0)); !ok {
			t.Fatal("a disabled limiter refused")
		}
	}
}

func TestRateBoundsItsMemory(t *testing.T) {
	r := NewRate(60)
	now := time.Unix(0, 0)
	for i := 0; i < maxKeys+10; i++ {
		r.Allow(fmt.Sprint(i), now)
	}
	if len(r.buckets) > maxKeys {
		t.Fatalf("%d buckets, want at most %d", len(r.buckets), maxKeys)
	}
	// A minute later every bucket has refilled, so a sweep makes room again.
	r.Allow("late", now.Add(time.Minute))
	if len(r.buckets) != 1 {
		t.Fatalf("%d buckets after the sweep, want 1", len(r.buckets))
	}
}

func TestBackoffDoublesAndCaps(t *testing.T) {
	b := NewBackoff(3, time.Second, 8*time.Second, time.Hour)
	now := time.Unix(0, 0)

	for i := 0; i < 3; i++ {
		b.Fail("alice", now)
		if w := b.Wait("alice", now); w != 0 {
			t.Fatalf("free failure %d imposed a wait of %v", i+1, w)
		}
	}
	for _, want := range []time.Duration{1, 2, 4, 8, 8} {
		b.Fail("alice", now)
		if w := b.Wait("alice", now); w != want*time.Second {
			t.Fatalf("wait = %v, want %v", w, want*time.Second)
		}
	}
	if w := b.Wait("bob", now); w != 0 {
		t.Fatalf("an untouched key waits %v", w)
	}

	b.Succeed("alice")
	if w := b.Wait("alice", now); w != 0 {
		t.Fatalf("wait after success = %v, want 0", w)
	}
}

func TestBackoffForgetsQuietKeys(t *testing.T) {
	b := NewBackoff(0, time.Second, time.Minute, time.Hour)
	now := time.Unix(0, 0)
	for i := 0; i < 5; i++ {
		b.Fail("alice", now)
	}
	later := now.Add(2 * time.Hour)
	if w := b.Wait("alice", later); w != 0 {
		t.Fatalf("wait after a quiet hour = %v, want 0", w)
	}
	b.Fail("alice", later)
	if w := b.Wait("alice", later); w != time.Second {
		t.Fatalf("first failure after forgetting waits %v, want 1s", w)
	}
}
