package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"kyrecovery-server/internal/crypto"
	"kyrecovery-server/internal/db"
)

const (
	SessionCookieName = "kyrecovery_session"
	SessionDuration   = 24 * time.Hour

	SettingSSOEnabled      = "sso.enabled"
	SettingSSOIssuerURL    = "sso.issuer_url"
	SettingSSOClientID     = "sso.client_id"
	SettingSSOClientSecret = "sso.client_secret"
	SettingSSORedirectURL  = "sso.redirect_url"
	SettingSSOAdminEmail   = "sso.admin_email"
)

// OIDCConfig holds settings for KySignOn OpenID Connect authentication.
type OIDCConfig struct {
	Enabled      bool   `json:"enabled"`
	IssuerURL    string `json:"issuer_url"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret,omitempty"`
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

// Manager handles OIDC login flows, PKCE challenges, local admin auth, and sessions.
type Manager struct {
	mu  sync.RWMutex
	cfg OIDCConfig
	db  *db.DB
}

// NewManager creates a new authentication manager.
func NewManager(cfg OIDCConfig, database *db.DB) *Manager {
	m := &Manager{
		cfg: cfg,
		db:  database,
	}
	m.loadSettingsFromDB(context.Background())
	return m
}

// loadSettingsFromDB loads saved SSO configurations from DB if available.
func (m *Manager) loadSettingsFromDB(ctx context.Context) {
	if m.db == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	if enabled, err := m.db.GetSetting(ctx, SettingSSOEnabled); err == nil && enabled != "" {
		m.cfg.Enabled = enabled == "true" || enabled == "1"
	}
	if issuer, err := m.db.GetSetting(ctx, SettingSSOIssuerURL); err == nil && issuer != "" {
		m.cfg.IssuerURL = issuer
	}
	if clientID, err := m.db.GetSetting(ctx, SettingSSOClientID); err == nil && clientID != "" {
		m.cfg.ClientID = clientID
	}
	if clientSecret, err := m.db.GetSetting(ctx, SettingSSOClientSecret); err == nil && clientSecret != "" {
		m.cfg.ClientSecret = clientSecret
	}
	if redirectURL, err := m.db.GetSetting(ctx, SettingSSORedirectURL); err == nil && redirectURL != "" {
		m.cfg.RedirectURL = redirectURL
	}
	if adminEmail, err := m.db.GetSetting(ctx, SettingSSOAdminEmail); err == nil && adminEmail != "" {
		m.cfg.AdminEmail = adminEmail
	}
}

// GetConfig returns the current OIDC SSO configuration.
func (m *Manager) GetConfig() OIDCConfig {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.cfg
}

// SaveConfig persists updated SSO configuration to SQLite and updates manager memory.
func (m *Manager) SaveConfig(ctx context.Context, cfg OIDCConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	enabledStr := "false"
	if cfg.Enabled {
		enabledStr = "true"
	}

	if err := m.db.SetSetting(ctx, SettingSSOEnabled, enabledStr); err != nil {
		return err
	}
	if err := m.db.SetSetting(ctx, SettingSSOIssuerURL, cfg.IssuerURL); err != nil {
		return err
	}
	if err := m.db.SetSetting(ctx, SettingSSOClientID, cfg.ClientID); err != nil {
		return err
	}
	if cfg.ClientSecret != "" && cfg.ClientSecret != "••••••••" {
		if err := m.db.SetSetting(ctx, SettingSSOClientSecret, cfg.ClientSecret); err != nil {
			return err
		}
		m.cfg.ClientSecret = cfg.ClientSecret
	}
	if err := m.db.SetSetting(ctx, SettingSSORedirectURL, cfg.RedirectURL); err != nil {
		return err
	}
	if err := m.db.SetSetting(ctx, SettingSSOAdminEmail, cfg.AdminEmail); err != nil {
		return err
	}

	m.cfg.Enabled = cfg.Enabled
	m.cfg.IssuerURL = cfg.IssuerURL
	m.cfg.ClientID = cfg.ClientID
	m.cfg.RedirectURL = cfg.RedirectURL
	m.cfg.AdminEmail = cfg.AdminEmail
	return nil
}

// IsEnabled returns true if SSO authentication is enabled and configured.
func (m *Manager) IsEnabled() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.cfg.Enabled && m.cfg.IssuerURL != "" && m.cfg.ClientID != ""
}

// HashPassword generates an Argon2id hash and salt for a password.
func HashPassword(password string) (hashHex, saltHex string, err error) {
	salt, err := crypto.GenerateRandomBytes(16)
	if err != nil {
		return "", "", err
	}
	key, err := crypto.DeriveKeyFromPassphrase(password, salt)
	if err != nil {
		return "", "", err
	}
	return hex.EncodeToString(key), hex.EncodeToString(salt), nil
}

// VerifyPassword validates a plaintext password against an Argon2id hash and salt.
func VerifyPassword(password, hashHex, saltHex string) bool {
	salt, err := hex.DecodeString(saltHex)
	if err != nil || len(salt) == 0 {
		return false
	}
	expectedKey, err := hex.DecodeString(hashHex)
	if err != nil || len(expectedKey) != crypto.KeyLength {
		return false
	}
	derivedKey, err := crypto.DeriveKeyFromPassphrase(password, salt)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(derivedKey, expectedKey) == 1
}

// GenerateRandomPassword creates a strong random password for first-time admin setup.
func GenerateRandomPassword(length int) (string, error) {
	if length < 12 {
		length = 16
	}
	const charset = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%&*+"
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	for i := range bytes {
		bytes[i] = charset[int(bytes[i])%len(charset)]
	}
	return string(bytes), nil
}

// EnsureAdminUser ensures an admin account exists, generating random credentials on first run.
func (m *Manager) EnsureAdminUser(ctx context.Context, initialPass string) (password string, isNew bool, err error) {
	existing, err := m.db.GetUserByUsername(ctx, "admin")
	if err != nil {
		return "", false, err
	}
	if existing != nil {
		return "", false, nil
	}

	pass := initialPass
	if pass == "" {
		pass, err = GenerateRandomPassword(16)
		if err != nil {
			return "", false, err
		}
	}

	hashHex, saltHex, err := HashPassword(pass)
	if err != nil {
		return "", false, fmt.Errorf("failed hashing admin password: %w", err)
	}

	now := time.Now().UTC()
	adminUser := db.UserRecord{
		ID:           "usr-admin-001",
		Username:     "admin",
		PasswordHash: hashHex,
		Salt:         saltHex,
		Email:        "admin@kyrecovery.local",
		Name:         "System Administrator",
		Role:         "admin",
		CreatedAt:    now,
	}

	if err := m.db.InsertUser(ctx, adminUser); err != nil {
		return "", false, fmt.Errorf("failed creating admin user: %w", err)
	}

	return pass, true, nil
}

// AuthenticateLocal validates local username and password and returns UserInfo.
func (m *Manager) AuthenticateLocal(ctx context.Context, username, password string) (*UserInfo, error) {
	username = strings.TrimSpace(username)
	if username == "" || password == "" {
		return nil, errors.New("username and password are required")
	}

	user, err := m.db.GetUserByUsername(ctx, username)
	if err != nil {
		return nil, fmt.Errorf("database query error: %w", err)
	}
	if user == nil {
		return nil, errors.New("invalid username or password")
	}

	if !VerifyPassword(password, user.PasswordHash, user.Salt) {
		return nil, errors.New("invalid username or password")
	}

	return &UserInfo{
		Subject: user.ID,
		Email:   user.Email,
		Name:    user.Name,
		Role:    user.Role,
	}, nil
}

// TestSSOConnection checks if the KySignOn OIDC discovery endpoint is reachable.
func (m *Manager) TestSSOConnection(ctx context.Context, issuerURL string) error {
	issuerURL = strings.TrimRight(strings.TrimSpace(issuerURL), "/")
	if issuerURL == "" {
		return errors.New("issuer URL is required")
	}

	discoveryURL := fmt.Sprintf("%s/.well-known/openid-configuration", issuerURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		// Fallback: ping root or authorize endpoint
		authReq, err2 := http.NewRequestWithContext(ctx, http.MethodGet, issuerURL, nil)
		if err2 == nil {
			if r2, err3 := client.Do(authReq); err3 == nil {
				defer r2.Body.Close()
				return nil
			}
		}
		return fmt.Errorf("could not connect to KySignOn issuer at %s: %w", issuerURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 && resp.StatusCode != http.StatusNotFound {
		return fmt.Errorf("issuer returned HTTP %d", resp.StatusCode)
	}

	return nil
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

// GetSession retrieves the current session from request cookie or Authorization header.
func (m *Manager) GetSession(ctx context.Context, r *http.Request) (*db.SessionRecord, error) {
	sessionID := ""
	if cookie, err := r.Cookie(SessionCookieName); err == nil && cookie.Value != "" {
		sessionID = cookie.Value
	} else if authHeader := r.Header.Get("Authorization"); strings.HasPrefix(authHeader, "Bearer ") {
		sessionID = strings.TrimPrefix(authHeader, "Bearer ")
	}
	if sessionID == "" {
		return nil, nil
	}
	return m.db.GetSession(ctx, sessionID)
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
