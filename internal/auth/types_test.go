package auth_test

import (
	"testing"
	"time"

	"idunapro/internal/auth"
)

func TestSubscriptionIsActive(t *testing.T) {
	now := time.Now().UTC()

	cases := []struct {
		name string
		sub  *auth.Subscription
		want bool
	}{
		{
			name: "nil subscription",
			sub:  nil,
			want: false,
		},
		{
			name: "active perpetual (zero ExpiresAt)",
			sub:  &auth.Subscription{Status: "active"},
			want: true,
		},
		{
			name: "active with future expiry",
			sub:  &auth.Subscription{Status: "active", ExpiresAt: now.Add(24 * time.Hour)},
			want: true,
		},
		{
			name: "active but expired",
			sub:  &auth.Subscription{Status: "active", ExpiresAt: now.Add(-24 * time.Hour)},
			want: false,
		},
		{
			name: "cancelled",
			sub:  &auth.Subscription{Status: "cancelled"},
			want: false,
		},
		{
			name: "expired status",
			sub:  &auth.Subscription{Status: "expired"},
			want: false,
		},
		{
			name: "cancelled but future expiry (status wins)",
			sub:  &auth.Subscription{Status: "cancelled", ExpiresAt: now.Add(24 * time.Hour)},
			want: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.sub.IsActive()
			if got != tc.want {
				t.Errorf("IsActive() = %v, want %v", got, tc.want)
			}
		})
	}
}
