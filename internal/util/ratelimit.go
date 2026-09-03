package util

import (
	"sync"
	"time"
)

type entry struct {
	count int
	until time.Time
}

type WindowRateLimiter struct {
	mu      sync.Mutex
	limit   int
	window  time.Duration
	entries map[string]entry
}

func NewWindowRateLimiter(limit int, window time.Duration) *WindowRateLimiter {
	return &WindowRateLimiter{limit: limit, window: window, entries: make(map[string]entry)}
}

func (r *WindowRateLimiter) Allow(key string, now time.Time) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	e := r.entries[key]
	if now.After(e.until) {
		e = entry{count: 0, until: now.Add(r.window)}
	}
	if e.count >= r.limit {
		r.entries[key] = e
		return false
	}
	e.count++
	r.entries[key] = e
	return true
}
