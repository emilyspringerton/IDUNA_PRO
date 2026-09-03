package middleware_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"idunapro/internal/http/middleware"
)

func okHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}

func TestRateLimitAllowsWithinLimit(t *testing.T) {
	lim := middleware.NewIPRateLimiter(10) // 10 req/min
	h := middleware.AuthRateLimit(lim)(http.HandlerFunc(okHandler))

	for i := 0; i < 10; i++ {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/local", nil)
		req.RemoteAddr = "1.2.3.4:1234"
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Errorf("request %d: want 200, got %d", i+1, rr.Code)
		}
	}
}

func TestRateLimitBlocks429(t *testing.T) {
	lim := middleware.NewIPRateLimiter(3) // only 3 req/min
	h := middleware.AuthRateLimit(lim)(http.HandlerFunc(okHandler))

	var got429 bool
	for i := 0; i < 5; i++ {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/local", nil)
		req.RemoteAddr = "5.6.7.8:9999"
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code == http.StatusTooManyRequests {
			got429 = true
			// Verify Retry-After header.
			if rr.Header().Get("Retry-After") == "" {
				t.Error("expected Retry-After header on 429")
			}
		}
	}
	if !got429 {
		t.Error("expected at least one 429 response after exceeding rate limit")
	}
}

func TestRateLimitDifferentIPs(t *testing.T) {
	lim := middleware.NewIPRateLimiter(1) // 1 req/min per IP
	h := middleware.AuthRateLimit(lim)(http.HandlerFunc(okHandler))

	ips := []string{"10.0.0.1:1", "10.0.0.2:1", "10.0.0.3:1"}
	for _, ip := range ips {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/local", nil)
		req.RemoteAddr = ip
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Errorf("first request from %s: want 200, got %d", ip, rr.Code)
		}
	}
}

func TestRateLimitXForwardedFor(t *testing.T) {
	lim := middleware.NewIPRateLimiter(1) // 1 req/min
	h := middleware.AuthRateLimit(lim)(http.HandlerFunc(okHandler))

	// First request — should pass.
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/local", nil)
	req.Header.Set("X-Forwarded-For", "192.168.1.1, 10.0.0.1")
	req.RemoteAddr = "10.0.0.1:0"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("first request: want 200, got %d", rr.Code)
	}

	// Second request from same XFF — should be rate-limited.
	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/auth/local", nil)
	req2.Header.Set("X-Forwarded-For", "192.168.1.1, 10.0.0.1")
	req2.RemoteAddr = "10.0.0.1:0"
	rr2 := httptest.NewRecorder()
	h.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusTooManyRequests {
		t.Errorf("second request: want 429, got %d", rr2.Code)
	}
}

func TestRateLimitAllow(t *testing.T) {
	lim := middleware.NewIPRateLimiter(5)
	if !lim.Allow("1.1.1.1") {
		t.Error("first allow should succeed")
	}
}
