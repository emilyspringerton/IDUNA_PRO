package device

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"idunapro/internal/auth"
	"idunapro/internal/util"
)

type fakeStore struct {
	req       *Request
	exchange  *Exchange
	user      *auth.User
	consumed  bool
	pollCount int
}

func (f *fakeStore) InsertDeviceRequest(ctx context.Context, req *Request) error { req.ID = 1; f.req = req; return nil }
func (f *fakeStore) GetDeviceRequestByDeviceHash(ctx context.Context, deviceHash [32]byte) (*Request, error) {
	if f.req == nil || f.req.DeviceCodeHash != deviceHash { return nil, sql.ErrNoRows }
	cp := *f.req
	if f.exchange != nil && !f.exchange.ConsumedAt.Valid {
		cp.ExchangePlain = sql.NullString{String: f.exchange.ExchangePlain, Valid: true}
		cp.ExchangeExpires = sql.NullTime{Time: f.exchange.ExpiresAt, Valid: true}
	}
	return &cp, nil
}
func (f *fakeStore) GetDeviceRequestByUserCode(ctx context.Context, userCodeNorm string) (*Request, error) { if f.req.UserCodeNorm != userCodeNorm { return nil, sql.ErrNoRows }; cp := *f.req; return &cp, nil }
func (f *fakeStore) UpdatePollState(ctx context.Context, requestID int64, lastPollAt time.Time) error { f.req.LastPollAt = sql.NullTime{Time: lastPollAt, Valid: true}; f.pollCount++; return nil }
func (f *fakeStore) AuthorizeRequest(ctx context.Context, requestID int64, userID []byte, ipHash [32]byte, uaHash [32]byte, now time.Time) error {
	f.req.Status = "authorized"; f.req.AuthorizedUserID = userID; return nil
}
func (f *fakeStore) UpsertExchangeForRequest(ctx context.Context, req *Request, exchange *Exchange) error { f.exchange = exchange; return nil }
func (f *fakeStore) GetExchangeByPlainOrHash(ctx context.Context, code string, hash [32]byte) (*Exchange, error) {
	if f.exchange == nil || f.exchange.ExchangeHash != hash || code != f.exchange.ExchangePlain { return nil, sql.ErrNoRows }
	return f.exchange, nil
}
func (f *fakeStore) ConsumeExchange(ctx context.Context, exchangeID int64, deviceRequestID int64, now time.Time) error {
	if f.consumed { return sql.ErrTxDone }
	f.consumed = true
	f.exchange.ConsumedAt = sql.NullTime{Time: now, Valid: true}
	return nil
}
func (f *fakeStore) LoadUserForToken(ctx context.Context, userID []byte) (*auth.User, error) { return f.user, nil }
func (f *fakeStore) AppendEvent(ctx context.Context, streamType, streamID, eventType string, payload []byte, occurredAt time.Time) error {
	return nil
}

func TestDeviceFlowAndSingleUseExchange(t *testing.T) {
	st := &fakeStore{user: &auth.User{Status: "active", Handle: "Hero", HonorAccepted: true, Roles: []string{"user"}}}
	svc := NewService(st)
	ctx := context.Background()
	start, err := svc.Start(ctx, "http://localhost/device")
	if err != nil { t.Fatal(err) }
	var uid [16]byte
	uid[0] = 7
	if err := svc.Confirm(ctx, start.UserCode, uid, util.SHA256Bytes([]byte("ip")), util.SHA256Bytes([]byte("ua"))); err != nil { t.Fatal(err) }
	poll, err := svc.Poll(ctx, start.DeviceCode)
	if err != nil { t.Fatal(err) }
	if poll.Status != "authorized" || poll.ExchangeCode == "" { t.Fatalf("unexpected poll: %+v", poll) }
	if _, err := svc.Exchange(ctx, poll.ExchangeCode); err != nil { t.Fatal(err) }
	if _, err := svc.Exchange(ctx, poll.ExchangeCode); err != ErrExchangeInvalid { t.Fatalf("want exchange invalid, got %v", err) }
}

func TestHonorHandleAndPollingGuards(t *testing.T) {
	st := &fakeStore{user: &auth.User{Status: "active", Handle: "", HonorAccepted: false}}
	now := time.Now().UTC()
	st.req = &Request{ID: 1, DeviceCodeHash: util.SHA256Bytes([]byte("d")), UserCodeNorm: "ABCD1234", UserCodeDisplay: "ABCD-1234", Status: "authorized", ExpiresAt: now.Add(10 * time.Minute), PollIntervalMS: 2000, LastPollAt: sql.NullTime{Time: now, Valid: true}, AuthorizedUserID: make([]byte, 16)}
	svc := NewService(st)
	if _, err := svc.Poll(context.Background(), "d"); err != ErrPollingTooFast { t.Fatalf("expected too fast") }
	st.req.LastPollAt = sql.NullTime{Time: now.Add(-3 * time.Second), Valid: true}
	poll, err := svc.Poll(context.Background(), "d")
	if err != nil { t.Fatal(err) }
	_, err = svc.Exchange(context.Background(), poll.ExchangeCode)
	if err != ErrHonorCodeRequired { t.Fatalf("expected honor required, got %v", err) }
	st.user.HonorAccepted = true
	_, err = svc.Exchange(context.Background(), poll.ExchangeCode)
	if err != ErrHandleRequired { t.Fatalf("expected handle required, got %v", err) }
}
