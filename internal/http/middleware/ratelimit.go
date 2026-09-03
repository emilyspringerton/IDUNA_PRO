// Package middleware: per-IP token-bucket rate limiter.
//
// AuthRateLimit wraps an http.Handler and enforces a token-bucket rate limit
// (default 10 req/min) per client IP. Excess requests are rejected with 429
// and a Retry-After header.
package middleware

import (
	"net"
	"net/http"
	"sync"
	"time"
)

// tokenBucket tracks the state for one client IP.
type tokenBucket struct {
	tokens     float64
	maxTokens  float64
	refillRate float64 // tokens per second
	lastRefill time.Time
	mu         sync.Mutex
}

// allow returns true if one token is available, false if the bucket is empty.
func (b *tokenBucket) allow() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	elapsed := now.Sub(b.lastRefill).Seconds()
	b.lastRefill = now
	b.tokens = min64(b.maxTokens, b.tokens+elapsed*b.refillRate)
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// IPRateLimiter is a concurrency-safe per-IP token-bucket limiter.
type IPRateLimiter struct {
	buckets    sync.Map // string(IP) → *tokenBucket
	maxTokens  float64
	refillRate float64 // tokens per second
}

// NewIPRateLimiter creates a limiter allowing ratePerMin requests per minute per IP.
// Burst = ratePerMin (full bucket at start).
func NewIPRateLimiter(ratePerMin int) *IPRateLimiter {
	rps := float64(ratePerMin) / 60.0
	return &IPRateLimiter{
		maxTokens:  float64(ratePerMin),
		refillRate: rps,
	}
}

func (l *IPRateLimiter) Allow(ip string) bool {
	v, _ := l.buckets.LoadOrStore(ip, &tokenBucket{
		tokens:     l.maxTokens,
		maxTokens:  l.maxTokens,
		refillRate: l.refillRate,
		lastRefill: time.Now(),
	})
	return v.(*tokenBucket).allow()
}

// AuthRateLimit returns middleware that applies the given IPRateLimiter.
// Requests from IPs that exceed the limit receive 429 Too Many Requests.
func AuthRateLimit(limiter *IPRateLimiter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := clientIP(r)
			if !limiter.Allow(ip) {
				w.Header().Set("Retry-After", "60")
				http.Error(w, "too many requests — try again in 60 seconds", http.StatusTooManyRequests)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// clientIP extracts the real client IP, preferring X-Forwarded-For.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Take the first (leftmost) IP in the chain.
		if idx := len(xff); idx > 0 {
			for i := 0; i < len(xff); i++ {
				if xff[i] == ',' {
					xff = xff[:i]
					break
				}
			}
		}
		if ip := net.ParseIP(xff); ip != nil {
			return ip.String()
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func min64(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}
