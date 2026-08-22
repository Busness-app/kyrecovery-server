package auth_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"kyrecovery-server/internal/auth"
	"kyrecovery-server/internal/db"
)

func TestPKCEGeneration(t *testing.T) {
	verifier, challenge, err := auth.GeneratePKCE()
	if err != nil {
		t.Fatalf("GeneratePKCE failed: %v", err)
	}
	if len(verifier) == 0 || len(challenge) == 0 {
		t.Fatalf("empty verifier or challenge")
	}
}

func TestSessionManagement(t *testing.T) {
	ctx := context.Background()
	database, err := db.Open(":memory:")
	if err != nil {
		t.Fatalf("db.Open failed: %v", err)
	}
	defer database.Close()

	mgr := auth.NewManager(auth.OIDCConfig{
		Enabled:    true,
		AdminEmail: "admin@kyrecovery.local",
	}, database)

	user := &auth.UserInfo{
		Subject: "usr-001",
		Email:   "admin@kyrecovery.local",
		Name:    "System Administrator",
		Role:    "admin",
	}

	cookie, err := mgr.CreateSession(ctx, user, true)
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}
	if cookie.Name != auth.SessionCookieName || cookie.Value == "" {
		t.Fatalf("unexpected cookie: %+v", cookie)
	}

	// Read session back
	req := httptest.NewRequest(http.MethodGet, "/api/auth/me", nil)
	req.AddCookie(cookie)

	session, err := mgr.GetSession(ctx, req)
	if err != nil || session == nil {
		t.Fatalf("GetSession failed: %v, session=%+v", err, session)
	}
	if session.Email != "admin@kyrecovery.local" || session.Role != "admin" {
		t.Fatalf("session data mismatch: %+v", session)
	}

	// Invalidate session
	clearCookie := mgr.InvalidateSession(ctx, req)
	if clearCookie.MaxAge != -1 {
		t.Fatalf("expected clear cookie with MaxAge -1")
	}

	// Verify session deleted
	sessionAfter, err := mgr.GetSession(ctx, req)
	if err != nil || sessionAfter != nil {
		t.Fatalf("expected nil session after deletion")
	}
}
