package twilio

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func testClient(t *testing.T, handler http.HandlerFunc) (*Client, func()) {
	t.Helper()
	srv := httptest.NewServer(handler)
	c := NewClient("AC_test", "SK_test", "secret_test")
	c.BaseURL = srv.URL
	c.TrunkingBaseURL = srv.URL
	return c, srv.Close
}

// TestClient_GetBalance_RealAuthAndDecode -- a real HTTP round trip against a fake server:
// Basic Auth header set correctly, real JSON decoded into the real Balance struct.
func TestClient_GetBalance_RealAuthAndDecode(t *testing.T) {
	c, closeFn := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != "SK_test" || pass != "secret_test" {
			t.Errorf("BasicAuth = (%q, %q, %v), want (SK_test, secret_test, true)", user, pass, ok)
		}
		json.NewEncoder(w).Encode(Balance{AccountSID: "AC_test", Balance: "20.00", Currency: "USD"})
	})
	defer closeFn()

	bal, err := c.GetBalance(context.Background())
	if err != nil {
		t.Fatalf("GetBalance: %v", err)
	}
	if bal.Balance != "20.00" || bal.Currency != "USD" {
		t.Errorf("balance = %+v, want Balance=20.00 Currency=USD", bal)
	}
}

// TestClient_CreateTrunk_SurfacesRealTwilioError is the real, decisive regression test for the
// real, live-found account-wide blocker (2026-09-05): a Twilio compliance error (code 20003)
// must reach the caller as the real, decoded message, not a generic wrapped error.
func TestClient_CreateTrunk_SurfacesRealTwilioError(t *testing.T) {
	c, closeFn := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(TwilioError{
			Code:     20003,
			Message:  "Primary compliance profile is not approved. Please refer to documentation and complete the KYC process in Trust Hub to gain access.",
			MoreInfo: "https://www.twilio.com/docs/errors/20003",
			Status:   401,
		})
	})
	defer closeFn()

	_, err := c.CreateTrunk(context.Background(), "CarePyre", "carepyre.pstn.twilio.com")
	if err == nil {
		t.Fatal("CreateTrunk: expected an error, got nil")
	}
	var terr *TwilioError
	if !isTwilioError(err, &terr) {
		t.Fatalf("CreateTrunk error is not a *TwilioError: %v (%T)", err, err)
	}
	if terr.Code != 20003 {
		t.Errorf("terr.Code = %d, want 20003", terr.Code)
	}
}

func isTwilioError(err error, out **TwilioError) bool {
	te, ok := err.(*TwilioError)
	if ok {
		*out = te
	}
	return ok
}

// TestClient_ListTrunks_Empty -- a real, empty trunks list decodes to a real, empty slice, not
// an error or a nil-panic.
func TestClient_ListTrunks_Empty(t *testing.T) {
	c, closeFn := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"trunks": []any{}})
	})
	defer closeFn()

	trunks, err := c.ListTrunks(context.Background())
	if err != nil {
		t.Fatalf("ListTrunks: %v", err)
	}
	if len(trunks) != 0 {
		t.Errorf("len(trunks) = %d, want 0", len(trunks))
	}
}

func TestClient_Configured(t *testing.T) {
	var nilClient *Client
	if nilClient.Configured() {
		t.Error("nil client should not be Configured")
	}
	if (&Client{}).Configured() {
		t.Error("empty client should not be Configured")
	}
	if !NewClient("AC1", "SK1", "secret1").Configured() {
		t.Error("client with all fields set should be Configured")
	}
}
