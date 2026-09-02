package auth_test

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Busness-app/kyrecovery-server/internal/auth"
)

// fakeIssuer is a minimal OIDC provider: discovery, JWKS and a token endpoint
// that hands back whichever ID token the test asked for by authorization code.
type fakeIssuer struct {
	*httptest.Server
	key    *rsa.PrivateKey
	tokens map[string]string
}

func newFakeIssuer(t *testing.T) *fakeIssuer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey failed: %v", err)
	}

	iss := &fakeIssuer{key: key, tokens: map[string]string{}}
	mux := http.NewServeMux()
	iss.Server = httptest.NewServer(mux)
	t.Cleanup(iss.Close)

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"issuer":                                iss.URL,
			"authorization_endpoint":                iss.URL + "/oauth/authorize",
			"token_endpoint":                        iss.URL + "/oauth/token",
			"userinfo_endpoint":                     iss.URL + "/oauth/userinfo",
			"jwks_uri":                              iss.URL + "/jwks",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"keys": []map[string]string{{
				"kty": "RSA",
				"kid": "test-key",
				"alg": "RS256",
				"use": "sig",
				"n":   b64u(key.N.Bytes()),
				"e":   b64u(big.NewInt(int64(key.E)).Bytes()),
			}},
		})
	})
	mux.HandleFunc("/oauth/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		idToken, ok := iss.tokens[r.FormValue("code")]
		if !ok {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "access-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
			"id_token":     idToken,
		})
	})
	return iss
}

func b64u(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// sign produces an RS256 JWT with the issuer's key.
func (f *fakeIssuer) sign(t *testing.T, key *rsa.PrivateKey, claims map[string]interface{}) string {
	t.Helper()
	header, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT", "kid": "test-key"})
	payload, _ := json.Marshal(claims)
	signingInput := b64u(header) + "." + b64u(payload)

	digest := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("signing failed: %v", err)
	}
	return signingInput + "." + b64u(sig)
}

// unsigned mimics the token an attacker crafts when claims are read without
// verifying the signature at all.
func unsigned(claims map[string]interface{}) string {
	header, _ := json.Marshal(map[string]string{"alg": "none", "typ": "JWT"})
	payload, _ := json.Marshal(claims)
	return b64u(header) + "." + b64u(payload) + "."
}

func TestExchangeCodeVerifiesIDToken(t *testing.T) {
	iss := newFakeIssuer(t)
	const clientID = "kyrecovery"
	const nonce = "nonce-abc123"

	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey failed: %v", err)
	}

	base := func() map[string]interface{} {
		return map[string]interface{}{
			"iss":   iss.URL,
			"aud":   clientID,
			"sub":   "user-1",
			"email": "operator@example.com",
			"name":  "Ops Person",
			"nonce": nonce,
			"exp":   time.Now().Add(time.Hour).Unix(),
			"iat":   time.Now().Unix(),
		}
	}
	withClaim := func(k string, v interface{}) map[string]interface{} {
		c := base()
		c[k] = v
		return c
	}

	// An attacker-controlled token endpoint claiming to be an admin.
	forged := base()
	forged["role"] = "admin"

	iss.tokens["valid"] = iss.sign(t, iss.key, base())
	iss.tokens["unsigned"] = unsigned(forged)
	iss.tokens["wrong-key"] = iss.sign(t, otherKey, forged)
	iss.tokens["wrong-audience"] = iss.sign(t, iss.key, withClaim("aud", "some-other-client"))
	iss.tokens["wrong-issuer"] = iss.sign(t, iss.key, withClaim("iss", "https://evil.example"))
	iss.tokens["expired"] = iss.sign(t, iss.key, withClaim("exp", time.Now().Add(-time.Hour).Unix()))
	iss.tokens["replayed-nonce"] = iss.sign(t, iss.key, withClaim("nonce", "a-different-login"))
	iss.tokens["no-nonce"] = iss.sign(t, iss.key, withClaim("nonce", ""))

	mgr := auth.NewManager(auth.OIDCConfig{
		Enabled:     true,
		IssuerURL:   iss.URL,
		ClientID:    clientID,
		RedirectURL: "http://localhost:8095/api/auth/callback",
	}, nil)

	ctx := context.Background()

	// The honest path still works.
	info, err := mgr.ExchangeCode(ctx, "valid", "verifier", nonce)
	if err != nil {
		t.Fatalf("valid ID token was rejected: %v", err)
	}
	if info.Subject != "user-1" || info.Email != "operator@example.com" {
		t.Fatalf("unexpected profile: %+v", info)
	}
	// A token with no role claim must not silently become an operator.
	if info.Role != auth.RoleViewer {
		t.Fatalf("expected least-privilege role for a token with no role claim, got %q", info.Role)
	}

	for _, code := range []string{"unsigned", "wrong-key", "wrong-audience", "wrong-issuer", "expired", "replayed-nonce", "no-nonce"} {
		if info, err := mgr.ExchangeCode(ctx, code, "verifier", nonce); err == nil {
			t.Errorf("%s ID token was accepted and produced role %q", code, info.Role)
		}
	}
}

// TestExchangeCodeRejectsMissingIDTokenWithoutUserinfo proves a failed token
// validation is never papered over by a second, unverified profile source.
func TestExchangeCodeRejectsMissingIDTokenWithoutUserinfo(t *testing.T) {
	iss := newFakeIssuer(t)
	iss.tokens["no-id-token"] = "" // token endpoint returns an empty id_token

	mgr := auth.NewManager(auth.OIDCConfig{
		Enabled: true, IssuerURL: iss.URL, ClientID: "kyrecovery",
	}, nil)

	if _, err := mgr.ExchangeCode(context.Background(), "no-id-token", "verifier", "nonce"); err == nil {
		t.Fatal("expected failure when the issuer returns no id_token and no working userinfo endpoint")
	}
}

func TestTestSSOConnectionRequiresDiscovery(t *testing.T) {
	mgr := auth.NewManager(auth.OIDCConfig{}, nil)
	ctx := context.Background()

	// A server that answers, but publishes no OIDC metadata, is not a usable issuer.
	bare := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("hello"))
	}))
	defer bare.Close()
	if err := mgr.TestSSOConnection(ctx, bare.URL); err == nil {
		t.Fatal("a plain HTTP responder was reported as a working KySignOn issuer")
	}

	// Schemes that are not http(s) never reach the network.
	for _, target := range []string{"file:///etc/passwd", "gopher://127.0.0.1:70/x", "ftp://internal/", ""} {
		if err := mgr.TestSSOConnection(ctx, target); err == nil {
			t.Errorf("issuer URL %q should have been rejected", target)
		}
	}

	// Link-local addresses (cloud metadata) are refused at dial time.
	err := mgr.TestSSOConnection(ctx, "http://169.254.169.254")
	if err == nil || !strings.Contains(fmt.Sprint(err), "169.254.169.254") {
		t.Fatalf("cloud metadata address should be blocked, got %v", err)
	}

	iss := newFakeIssuer(t)
	if err := mgr.TestSSOConnection(ctx, iss.URL); err != nil {
		t.Fatalf("a real issuer should pass: %v", err)
	}
}
