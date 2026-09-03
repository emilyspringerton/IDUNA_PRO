package handlers_test

import (
	"context"
	"time"

	"idunapro/internal/auth"
	"idunapro/internal/store"
)

// noopGFDTiers embeds in test stubs to satisfy the GFD tier IAMStore methods.
// All stubs that don't test GFD tier functionality embed this.
type noopGFDTiers struct{}

func (noopGFDTiers) ListSubscriptionTiers(_ context.Context) ([]store.GFDTier, error) {
	return nil, nil
}
func (noopGFDTiers) GetGFDUserTier(_ context.Context, _ string) (*string, error) { return nil, nil }
func (noopGFDTiers) SetGFDUserTier(_ context.Context, _, _ string) error         { return nil }
func (noopGFDTiers) RecordStripeEvent(_ context.Context, _, _, _, _ string) error { return nil }

// noopMonitors embeds in test stubs to satisfy the monitors IAMStore methods.
type noopMonitors struct{}

func (noopMonitors) CreateMonitor(_ context.Context, _ auth.Monitor) (int64, error) { return 0, nil }
func (noopMonitors) GetMonitorBySlug(_ context.Context, _ string) (*auth.Monitor, error) {
	return nil, nil
}
func (noopMonitors) GetMonitorByID(_ context.Context, _ int64) (*auth.Monitor, error) {
	return nil, nil
}
func (noopMonitors) ListMonitors(_ context.Context, _ string) ([]auth.Monitor, error) {
	return nil, nil
}
func (noopMonitors) UpdateMonitor(_ context.Context, _ auth.Monitor) error            { return nil }
func (noopMonitors) RecordCheckin(_ context.Context, _ string, _ time.Time) error     { return nil }
func (noopMonitors) MarkMonitorAlerted(_ context.Context, _ int64, _ time.Time) error { return nil }
func (noopMonitors) RecoverMonitor(_ context.Context, _ int64, _ time.Time) error     { return nil }
func (noopMonitors) ListOverdueMonitors(_ context.Context, _ time.Time) ([]auth.Monitor, error) {
	return nil, nil
}
func (noopMonitors) DeleteMonitor(_ context.Context, _ int64) error { return nil }
