package device

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"errors"
	"time"

		"idunapro/internal/auth"
	"idunapro/internal/util"
)

var (
	ErrInvalidOrExpired   = errors.New("DEVICE_CODE_INVALID_OR_EXPIRED")
	ErrPollingTooFast     = errors.New("POLLING_TOO_FAST")
	ErrExchangeInvalid    = errors.New("EXCHANGE_CODE_INVALID")
	ErrHonorCodeRequired  = errors.New("HONOR_CODE_REQUIRED")
	ErrHandleRequired     = errors.New("HANDLE_REQUIRED")
	ErrAccountSuspended   = errors.New("ACCOUNT_SUSPENDED")
	ErrUnauthenticatedWeb = errors.New("UNAUTHENTICATED")
)

type Request struct {
	ID               int64
	StreamID         string
	DeviceCodeHash   [32]byte
	UserCodeNorm     string
	UserCodeDisplay  string
	Status           string
	ExpiresAt        time.Time
	PollIntervalMS   int
	LastPollAt       sql.NullTime
	AuthorizedUserID []byte
	ExchangePlain    sql.NullString
	ExchangeExpires  sql.NullTime
}

type Exchange struct {
	ID             int64
	ExchangeHash   [32]byte
	ExchangePlain  string
	UserID         []byte
	DeviceRequest  int64
	ExpiresAt      time.Time
	ConsumedAt     sql.NullTime
}

type Store interface {
	InsertDeviceRequest(ctx context.Context, req *Request) error
	GetDeviceRequestByDeviceHash(ctx context.Context, deviceHash [32]byte) (*Request, error)
	GetDeviceRequestByUserCode(ctx context.Context, userCodeNorm string) (*Request, error)
	UpdatePollState(ctx context.Context, requestID int64, lastPollAt time.Time) error
	AuthorizeRequest(ctx context.Context, requestID int64, userID []byte, ipHash [32]byte, uaHash [32]byte, now time.Time) error
	UpsertExchangeForRequest(ctx context.Context, req *Request, exchange *Exchange) error
	GetExchangeByPlainOrHash(ctx context.Context, code string, hash [32]byte) (*Exchange, error)
	ConsumeExchange(ctx context.Context, exchangeID int64, deviceRequestID int64, now time.Time) error
	LoadUserForToken(ctx context.Context, userID []byte) (*auth.User, error)
	AppendEvent(ctx context.Context, streamType, streamID, eventType string, payload []byte, occurredAt time.Time) error
}

type Service struct {
	store Store
	now   func() time.Time
}

func NewService(store Store) *Service {
	return &Service{store: store, now: func() time.Time { return time.Now().UTC() }}
}

type StartResponse struct {
	DeviceCode      string `json:"device_code"`
	UserCode        string `json:"user_code"`
	VerificationURL string `json:"verification_url"`
	ExpiresIn       int    `json:"expires_in"`
	Interval        int    `json:"interval"`
}

func (s *Service) Start(ctx context.Context, verificationURL string) (*StartResponse, error) {
	deviceCode, err := util.Base64URLRandom(32)
	if err != nil {
		return nil, err
	}
	display, norm, err := util.GenerateUserCode()
	if err != nil {
		return nil, err
	}
	now := s.now()
	expires := now.Add(15 * time.Minute)
	hash := util.SHA256Bytes([]byte(deviceCode))
	streamID, err := util.Base64URLRandom(18)
	if err != nil {
		return nil, err
	}

	req := &Request{DeviceCodeHash: hash, UserCodeNorm: norm, UserCodeDisplay: display, Status: "pending", ExpiresAt: expires, PollIntervalMS: 2000, StreamID: streamID}
	if err := s.store.InsertDeviceRequest(ctx, req); err != nil {
		return nil, err
	}
	_ = s.store.AppendEvent(ctx, "device_auth", streamID, "DeviceAuthStarted", []byte(`{"user_code_display":"`+display+`"}`), now)

	return &StartResponse{DeviceCode: deviceCode, UserCode: display, VerificationURL: verificationURL, ExpiresIn: int(time.Until(expires).Seconds()), Interval: 2}, nil
}

type PollResponse struct {
	Status       string `json:"status"`
	Interval     int    `json:"interval,omitempty"`
	ExpiresIn    int    `json:"expires_in"`
	ExchangeCode string `json:"exchange_code,omitempty"`
}

func (s *Service) Poll(ctx context.Context, deviceCode string) (*PollResponse, error) {
	now := s.now()
	hash := util.SHA256Bytes([]byte(deviceCode))
	req, err := s.store.GetDeviceRequestByDeviceHash(ctx, hash)
	if err != nil {
		return nil, ErrInvalidOrExpired
	}
	if now.After(req.ExpiresAt) {
		return nil, ErrInvalidOrExpired
	}
	if req.LastPollAt.Valid {
		elapsed := now.Sub(req.LastPollAt.Time)
		if elapsed < time.Duration(req.PollIntervalMS)*time.Millisecond {
			return nil, ErrPollingTooFast
		}
	}
	if err := s.store.UpdatePollState(ctx, req.ID, now); err != nil {
		return nil, err
	}
	if req.Status != "authorized" {
		return &PollResponse{Status: "pending", Interval: req.PollIntervalMS / 1000, ExpiresIn: int(time.Until(req.ExpiresAt).Seconds())}, nil
	}
	if req.ExchangePlain.Valid && req.ExchangeExpires.Valid && now.Before(req.ExchangeExpires.Time) {
		return &PollResponse{Status: "authorized", ExchangeCode: req.ExchangePlain.String, ExpiresIn: int(time.Until(req.ExchangeExpires.Time).Seconds())}, nil
	}
	plain, err := util.Base64URLRandom(32)
	if err != nil {
		return nil, err
	}
	exp := now.Add(60 * time.Second)
	ex := &Exchange{ExchangeHash: util.SHA256Bytes([]byte(plain)), ExchangePlain: plain, UserID: req.AuthorizedUserID, DeviceRequest: req.ID, ExpiresAt: exp}
	if err := s.store.UpsertExchangeForRequest(ctx, req, ex); err != nil {
		return nil, err
	}
	return &PollResponse{Status: "authorized", ExchangeCode: plain, ExpiresIn: 60}, nil
}

func (s *Service) Confirm(ctx context.Context, userCode string, userID [16]byte, ipHash [32]byte, uaHash [32]byte) error {
	now := s.now()
	norm := util.NormalizeUserCode(userCode)
	req, err := s.store.GetDeviceRequestByUserCode(ctx, norm)
	if err != nil {
		return ErrInvalidOrExpired
	}
	if req.Status != "pending" || now.After(req.ExpiresAt) {
		return ErrInvalidOrExpired
	}
	uid := userID[:]
	if err := s.store.AuthorizeRequest(ctx, req.ID, uid, ipHash, uaHash, now); err != nil {
		return err
	}
	plain, err := util.Base64URLRandom(32)
	if err != nil {
		return err
	}
	ex := &Exchange{ExchangeHash: util.SHA256Bytes([]byte(plain)), ExchangePlain: plain, UserID: uid, DeviceRequest: req.ID, ExpiresAt: now.Add(60 * time.Second)}
	if err := s.store.UpsertExchangeForRequest(ctx, req, ex); err != nil {
		return err
	}
	_ = s.store.AppendEvent(ctx, "device_auth", req.StreamID, "DeviceAuthAuthorized", []byte(`{"authorized_at":"`+now.Format(time.RFC3339Nano)+`"}`), now)
	return nil
}

func (s *Service) Exchange(ctx context.Context, exchangeCode string) (*auth.User, error) {
	now := s.now()
	hash := util.SHA256Bytes([]byte(exchangeCode))
	ex, err := s.store.GetExchangeByPlainOrHash(ctx, exchangeCode, hash)
	if err != nil {
		return nil, ErrExchangeInvalid
	}
	if ex.ConsumedAt.Valid || now.After(ex.ExpiresAt) {
		return nil, ErrExchangeInvalid
	}
	plainHash := util.SHA256Bytes([]byte(ex.ExchangePlain))
	if subtle.ConstantTimeCompare(plainHash[:], hash[:]) != 1 {
		return nil, ErrExchangeInvalid
	}
	usr, err := s.store.LoadUserForToken(ctx, ex.UserID)
	if err != nil {
		return nil, err
	}
	if usr.Status == "suspended" {
		return usr, ErrAccountSuspended
	}
	if !usr.HonorAccepted {
		return usr, ErrHonorCodeRequired
	}
	if usr.Handle == "" {
		return usr, ErrHandleRequired
	}
	if err := s.store.ConsumeExchange(ctx, ex.ID, ex.DeviceRequest, now); err != nil {
		return nil, err
	}
	_ = s.store.AppendEvent(ctx, "device_auth", "device-"+hex.EncodeToString(ex.UserID), "DeviceAuthExchanged", []byte(`{"client":"kikoryu"}`), now)
	return usr, nil
}
