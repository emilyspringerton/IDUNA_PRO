package store_test

import (
	"context"
	"errors"
	"testing"

	"idunapro/internal/store"
)

func setupCeremonyStore(t *testing.T) *store.SQLiteStore {
	t.Helper()
	db, err := store.OpenSQLite(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := store.RunSQLiteMigrations(db, "../../migrations/truestore"); err != nil {
		t.Fatalf("run migrations: %v", err)
	}
	return store.NewSQLiteStore(db)
}

// TestAcceptHonorCode_RecordsAcceptance verifies the write path that,
// before this change, did not exist anywhere in the codebase: nothing ever
// set honor_accepted_current/honor_code_sha/honor_code_version.
func TestAcceptHonorCode_RecordsAcceptance(t *testing.T) {
	s := setupCeremonyStore(t)
	ctx := context.Background()

	user, _, err := s.GetOrCreateUserByGoogleSubject(ctx, "sub-1", "user1@example.com")
	if err != nil {
		t.Fatalf("GetOrCreateUserByGoogleSubject: %v", err)
	}
	if user.HonorAccepted {
		t.Fatalf("brand new user should not have accepted the honor code yet")
	}

	if err := s.AcceptHonorCode(ctx, user.IDString, 1, "deadbeef", "the text", user.IDString); err != nil {
		t.Fatalf("AcceptHonorCode: %v", err)
	}

	got, err := s.GetUserByID(ctx, user.IDString)
	if err != nil {
		t.Fatalf("GetUserByID: %v", err)
	}
	if !got.HonorAccepted {
		t.Errorf("expected HonorAccepted true after AcceptHonorCode")
	}
	if got.HonorCurrentSHA != "deadbeef" {
		t.Errorf("expected sha 'deadbeef', got %q", got.HonorCurrentSHA)
	}
	if got.HonorCurrentVer != 1 {
		t.Errorf("expected version 1, got %d", got.HonorCurrentVer)
	}
}

// TestClaimHandle_Succeeds verifies a fresh user can claim a gamertag.
func TestClaimHandle_Succeeds(t *testing.T) {
	s := setupCeremonyStore(t)
	ctx := context.Background()

	user, _, err := s.GetOrCreateUserByGoogleSubject(ctx, "sub-2", "user2@example.com")
	if err != nil {
		t.Fatalf("GetOrCreateUserByGoogleSubject: %v", err)
	}

	if err := s.ClaimHandle(ctx, user.IDString, "TestPlayer", user.IDString); err != nil {
		t.Fatalf("ClaimHandle: %v", err)
	}

	got, err := s.GetUserByID(ctx, user.IDString)
	if err != nil {
		t.Fatalf("GetUserByID: %v", err)
	}
	if got.Handle != "TestPlayer" {
		t.Errorf("expected handle 'TestPlayer', got %q", got.Handle)
	}
}

// TestClaimHandle_ImmutableOnceSet verifies gamertags are permanent --
// a second claim by the same user fails with ErrHandleAlreadySet, per
// VS0_IDENTITY_GATE.md's "one identity, one name, forever."
func TestClaimHandle_ImmutableOnceSet(t *testing.T) {
	s := setupCeremonyStore(t)
	ctx := context.Background()

	user, _, err := s.GetOrCreateUserByGoogleSubject(ctx, "sub-3", "user3@example.com")
	if err != nil {
		t.Fatalf("GetOrCreateUserByGoogleSubject: %v", err)
	}
	if err := s.ClaimHandle(ctx, user.IDString, "FirstPick", user.IDString); err != nil {
		t.Fatalf("first ClaimHandle: %v", err)
	}
	err = s.ClaimHandle(ctx, user.IDString, "SecondPick", user.IDString)
	if !errors.Is(err, store.ErrHandleAlreadySet) {
		t.Fatalf("expected ErrHandleAlreadySet, got %v", err)
	}
}

// TestClaimHandle_RejectsDuplicate verifies two different users cannot
// claim the same exact gamertag.
func TestClaimHandle_RejectsDuplicate(t *testing.T) {
	s := setupCeremonyStore(t)
	ctx := context.Background()

	u1, _, err := s.GetOrCreateUserByGoogleSubject(ctx, "sub-4", "user4@example.com")
	if err != nil {
		t.Fatalf("GetOrCreateUserByGoogleSubject u1: %v", err)
	}
	u2, _, err := s.GetOrCreateUserByGoogleSubject(ctx, "sub-5", "user5@example.com")
	if err != nil {
		t.Fatalf("GetOrCreateUserByGoogleSubject u2: %v", err)
	}

	if err := s.ClaimHandle(ctx, u1.IDString, "SameName", u1.IDString); err != nil {
		t.Fatalf("first ClaimHandle: %v", err)
	}
	err = s.ClaimHandle(ctx, u2.IDString, "SameName", u2.IDString)
	if !errors.Is(err, store.ErrHandleTaken) {
		t.Fatalf("expected ErrHandleTaken, got %v", err)
	}
}

// TestIsHandleAvailable verifies availability checks reflect claimed state.
func TestIsHandleAvailable(t *testing.T) {
	s := setupCeremonyStore(t)
	ctx := context.Background()

	avail, err := s.IsHandleAvailable(ctx, "FreshName")
	if err != nil {
		t.Fatalf("IsHandleAvailable: %v", err)
	}
	if !avail {
		t.Fatalf("expected FreshName to be available before anyone claims it")
	}

	user, _, err := s.GetOrCreateUserByGoogleSubject(ctx, "sub-6", "user6@example.com")
	if err != nil {
		t.Fatalf("GetOrCreateUserByGoogleSubject: %v", err)
	}
	if err := s.ClaimHandle(ctx, user.IDString, "FreshName", user.IDString); err != nil {
		t.Fatalf("ClaimHandle: %v", err)
	}

	avail, err = s.IsHandleAvailable(ctx, "FreshName")
	if err != nil {
		t.Fatalf("IsHandleAvailable after claim: %v", err)
	}
	if avail {
		t.Errorf("expected FreshName to be unavailable after being claimed")
	}
}
