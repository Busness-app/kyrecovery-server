package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"kyrecovery-server/internal/db"
)

const (
	SessionCookieName = "kyrecovery_session"
	SessionDuration   = 24 * time.Hour
)

// OIDCConfig holds settings for KySignOn OpenID Connect authentication.
type OIDCConfig struct {
	Enabled      bool   `json:"enabled"`
	IssuerURL    string `json:"issuer_url"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	RedirectURL  string `json:"redirect_url"`
	AdminEmail   string `json:"admin_email"`
}

// UserInfo represents an authenticated user profile.
type UserInfo struct {
	Subject string `json:"sub"`
	Email   string `json:"email"`
	Name    string `json:"name"`
	Role    string `json:"role"` // "admin", "operator", "viewer"
}

// Manager handles OIDC login flows, PKCE challenges, token exchange, and sessions.
type Manager struct {
	cfg OIDCConfig
	db  *db.DB
}

// NewManager creates a new authentication manager.
func NewManager(cfg OIDCConfig, database *db.DB) *Manager {
	return &Manager{
		cfg: cfg,
		db:  database,
	}
}

// IsEnabled returns true if SSO authentication is enabled.
func (m *Manager) IsEnabled() bool {
	return m.cfg.Enabled && m.cfg.IssuerURL != "" && m.cfg.ClientID != ""
}

// GeneratePKCE creates a cryptographic code verifier and S256 code challenge.
func GeneratePKCE() (verifier, challenge string, err error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", err
	}
	verifier = base64.RawURLEncoding.EncodeToString(b)
	h := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(h[:])
	return verifier, challenge, nil
}

// GenerateRandomString generates a secure random hex string.
func GenerateRandomString(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// BuildAuthURL creates the KySignOn authorization URL with PKCE.
func (m *Manager) BuildAuthURL(state, nonce, codeChallenge string) string {
	authEndpoint := fmt.Sprintf("%s/oauth/authorize", strings.TrimRight(m.cfg.IssuerURL, "/"))
	params := url.Values{}
	params.Set("client_id", m.cfg.ClientID)
	params.Set("response_type", "code")
	params.Set("scope", "openid profile email")
	params.Set("redirect_uri", m.cfg.RedirectURL)
	params.Set("state", state)
	params.Set("nonce", nonce)
	params.Set("code_challenge", codeChallenge)
	params.Set("code_challenge_method", "S256")
	return fmt.Sprintf("%s?%s", authEndpoint, params.Encode())
}

// TokenResponse represents the token endpoint response from KySignOn.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	IDToken      string `json:"id_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

// ExchangeCode exchanges an authorization code and PKCE verifier for user info.
func (m *Manager) ExchangeCode(ctx context.Context, code, verifier string) (*UserInfo, error) {
	tokenEndpoint := fmt.Sprintf("%s/oauth/token", strings.TrimRight(m.cfg.IssuerURL, "/"))

	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("redirect_uri", m.cfg.RedirectURL)
	data.Set("client_id", m.cfg.ClientID)
	data.Set("client_secret", m.cfg.ClientSecret)
	data.Set("code_verifier", verifier)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenEndpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed creating token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token exchange failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("token endpoint returned %d: %s", resp.StatusCode, string(body))
	}

	var tokResp TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokResp); err != nil {
		return nil, fmt.Errorf("failed decoding token response: %w", err)
	}

	// Parse ID Token claims (or fetch userinfo endpoint)
	userInfo, err := m.parseIDToken(tokResp.IDToken)
	if err != nil {
		// Fallback to /oauth/userinfo
		userInfo, err = m.fetchUserInfo(ctx, tokResp.AccessToken)
		if err != nil {
			return nil, fmt.Errorf("failed retrieving user profile: %w", err)
		}
	}

	// Assign role
	if m.cfg.AdminEmail != "" && strings.EqualFold(userInfo.Email, m.cfg.AdminEmail) {
		userInfo.Role = "admin"
	} else if userInfo.Role == "" {
		userInfo.Role = "operator"
	}

	return userInfo, nil
}

func (m *Manager) parseIDToken(idToken string) (*UserInfo, error) {
	parts := strings.Split(idToken, ".")
	if len(parts) < 2 {
		return nil, errors.New("invalid jwt token format")
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}

	var claims struct {
		Sub   string   `json:"sub"`
		Email string   `json:"email"`
		Name  string   `json:"name"`
		Role  string   `json:"role"`
		Roles []string `json:"roles"`
	}
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, err
	}

	role := claims.Role
	if role == "" && len(claims.Roles) > 0 {
		role = claims.Roles[0]
	}

	return &UserInfo{
		Subject: claims.Sub,
		Email:   claims.Email,
		Name:    claims.Name,
		Role:    role,
	}, nil
}

func (m *Manager) fetchUserInfo(ctx context.Context, accessToken string) (*UserInfo, error) {
	userInfoEndpoint := fmt.Sprintf("%s/oauth/userinfo", strings.TrimRight(m.cfg.IssuerURL, "/"))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, userInfoEndpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("userinfo endpoint returned %d", resp.StatusCode)
	}

	var claims struct {
		Sub   string `json:"sub"`
		Email string `json:"email"`
		Name  string `json:"name"`
		Role  string `json:"role"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&claims); err != nil {
		return nil, err
	}

	return &UserInfo{
		Subject: claims.Sub,
		Email:   claims.Email,
		Name:    claims.Name,
		Role:    claims.Role,
	}, nil
}

// CreateSession registers a new authenticated session in SQLite and returns a session cookie.
func (m *Manager) CreateSession(ctx context.Context, u *UserInfo) (*http.Cookie, error) {
	sessionID, err := GenerateRandomString(24)
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	rec := db.SessionRecord{
		ID:        sessionID,
		UserID:    u.Subject,
		Email:     u.Email,
		Name:      u.Name,
		Role:      u.Role,
		ExpiresAt: now.Add(SessionDuration),
		CreatedAt: now,
	}

	if err := m.db.InsertSession(ctx, rec); err != nil {
		return nil, fmt.Errorf("failed storing session: %w", err)
	}

	cookie := &http.Cookie{
		Name:     SessionCookieName,
		Value:    sessionID,
		Path:     "/",
		Expires:  rec.ExpiresAt,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}

	return cookie, nil
}

// GetSession retrieves the current session from request cookie.
func (m *Manager) GetSession(ctx context.Context, r *http.Request) (*db.SessionRecord, error) {
	cookie, err := r.Cookie(SessionCookieName)
	if err != nil || cookie.Value == "" {
		return nil, nil
	}
	return m.db.GetSession(ctx, cookie.Value)
}

// InvalidateSession deletes the current session and clears the cookie.
func (m *Manager) InvalidateSession(ctx context.Context, r *http.Request) *http.Cookie {
	if cookie, err := r.Cookie(SessionCookieName); err == nil && cookie.Value != "" {
		_ = m.db.DeleteSession(ctx, cookie.Value)
	}
	return &http.Cookie{
		Name:     SessionCookieName,
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
}
