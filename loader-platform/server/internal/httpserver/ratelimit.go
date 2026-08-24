package httpserver

import (
	"sync"
	"time"
)

type rateEntry struct {
	windowStart time.Time
	count       int
	lastSeen    time.Time
}

type rateLimiter struct {
	mu      sync.Mutex
	entries map[string]rateEntry
}

func newRateLimiter() *rateLimiter {
	return &rateLimiter{entries: make(map[string]rateEntry)}
}

func (r *rateLimiter) allow(key string, limit int, window time.Duration) bool {
	now := time.Now()
	r.mu.Lock()
	defer r.mu.Unlock()

	entry := r.entries[key]
	if entry.windowStart.IsZero() || now.Sub(entry.windowStart) >= window {
		entry.windowStart = now
		entry.count = 0
	}
	entry.count++
	entry.lastSeen = now
	r.entries[key] = entry
	return entry.count <= limit
}

func (r *rateLimiter) prune(maxAge time.Duration) {
	cutoff := time.Now().Add(-maxAge)
	r.mu.Lock()
	defer r.mu.Unlock()
	for key, entry := range r.entries {
		if entry.lastSeen.Before(cutoff) {
			delete(r.entries, key)
		}
	}
}
