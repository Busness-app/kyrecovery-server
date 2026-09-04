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
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/Busness-app/ky-primitives/password"
	"github.com/Busness-app/kyrecovery-server/internal/db"
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

	// provider caches the discovered issuer metadata and its JWKS between logins.
	providerMu     sync.Mutex
	provider       *oidc.Provider
	providerIssuer string
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
		if opened, err := m.db.Keyring().Open(clientSecret); err == nil {
			m.cfg.ClientSecret = opened
		}
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
		sealed, err := m.db.Keyring().Seal(cfg.ClientSecret)
		if err != nil {
			return err
		}
		if err := m.db.SetSetting(ctx, SettingSSOClientSecret, sealed); err != nil {
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

// HashPassword generates a PHC-encoded Argon2id hash for a password.
func HashPassword(plaintext string) (string, error) {
	return password.Hash(plaintext)
}

// VerifyPassword validates a plaintext password against a PHC-encoded hash.
func VerifyPassword(plaintext, encoded string) bool {
	ok, err := password.Verify(plaintext, encoded)
	return err == nil && ok
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

	hash, err := HashPassword(pass)
	if err != nil {
		return "", false, fmt.Errorf("failed hashing admin password: %w", err)
	}

	now := time.Now().UTC()
	adminUser := db.UserRecord{
		ID:           "usr-admin-001",
		Username:     "admin",
		PasswordHash: hash,
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

	if !VerifyPassword(password, user.PasswordHash) {
		return nil, errors.New("invalid username or password")
	}

	return &UserInfo{
		Subject: user.ID,
		Email:   user.Email,
		Name:    user.Name,
		Role:    user.Role,
	}, nil
}

// httpClient is the outbound client used for every issuer request. Its dialer
// refuses link-local destinations (including the 169.254.169.254 cloud metadata
// service) at connect time, so redirects and DNS rebinding are covered too.
//
// Loopback and RFC1918 addresses are deliberately allowed: a homelab KySignOn
// normally lives on the same LAN, and this path is admin-only.
var httpClient = sync.OnceValue(func() *http.Client {
	dialer := &net.Dialer{
		Timeout: 5 * time.Second,
		Control: func(network, address string, _ syscall.RawConn) error {
			if network != "tcp4" && network != "tcp6" {
				return fmt.Errorf("blocked network %q", network)
			}
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return err
			}
			ip := net.ParseIP(host)
			if ip == nil {
				return fmt.Errorf("unresolvable address %q", address)
			}
			if ip.IsUnspecified() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() {
				return fmt.Errorf("blocked issuer address %s", ip)
			}
			return nil
		},
	}
	return &http.Client{
		Timeout:   10 * time.Second,
		Transport: &http.Transport{DialContext: dialer.DialContext},
		CheckRedirect: func(_ *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return errors.New("too many redirects from issuer")
			}
			return nil
		},
	}
})

// validateIssuerURL rejects issuer URLs that are not plain http(s) origins.
func validateIssuerURL(issuerURL string) (string, error) {
	issuerURL = strings.TrimRight(strings.TrimSpace(issuerURL), "/")
	if issuerURL == "" {
		return "", errors.New("issuer URL is required")
	}
	u, err := url.Parse(issuerURL)
	if err != nil {
		return "", fmt.Errorf("invalid issuer URL: %w", err)
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return "", fmt.Errorf("issuer URL scheme %q is not supported (use https)", u.Scheme)
	}
	if u.Host == "" {
		return "", errors.New("issuer URL is missing a host")
	}
	if u.User != nil {
		return "", errors.New("issuer URL must not contain credentials")
	}
	return issuerURL, nil
}

// oidcProvider returns the cached OIDC provider for the configured issuer,
// running discovery (and the JWKS fetch) once per issuer.
func (m *Manager) oidcProvider(ctx context.Context) (*oidc.Provider, error) {
	issuer, err := validateIssuerURL(m.GetConfig().IssuerURL)
	if err != nil {
		return nil, err
	}

	m.providerMu.Lock()
	defer m.providerMu.Unlock()
	if m.provider != nil && m.providerIssuer == issuer {
		return m.provider, nil
	}

	p, err := oidc.NewProvider(oidc.ClientContext(ctx, httpClient()), issuer)
	if err != nil {
		return nil, fmt.Errorf("OIDC discovery failed for %s: %w", issuer, err)
	}
	m.provider, m.providerIssuer = p, issuer
	return p, nil
}

// TestSSOConnection checks that the issuer publishes usable OIDC discovery metadata.
func (m *Manager) TestSSOConnection(ctx context.Context, issuerURL string) error {
	issuerURL, err := validateIssuerURL(issuerURL)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	// Discovery is what KyRecovery actually needs at login: it carries the
	// endpoints and the JWKS used to verify ID tokens. A bare TCP connect is
	// not evidence the issuer works, so it is not accepted as a fallback.
	if _, err := oidc.NewProvider(oidc.ClientContext(ctx, httpClient()), issuerURL); err != nil {
		return fmt.Errorf("could not read OIDC discovery document from %s: %w", issuerURL, err)
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

// BuildAuthURL creates the KySignOn authorization URL with PKCE, using the
// authorization endpoint published by the issuer's discovery document.
func (m *Manager) BuildAuthURL(ctx context.Context, state, nonce, codeChallenge string) (string, error) {
	provider, err := m.oidcProvider(ctx)
	if err != nil {
		return "", err
	}
	cfg := m.GetConfig()

	params := url.Values{}
	params.Set("client_id", cfg.ClientID)
	params.Set("response_type", "code")
	params.Set("scope", "openid profile email")
	params.Set("redirect_uri", cfg.RedirectURL)
	params.Set("state", state)
	params.Set("nonce", nonce)
	params.Set("code_challenge", codeChallenge)
	params.Set("code_challenge_method", "S256")
	return fmt.Sprintf("%s?%s", provider.Endpoint().AuthURL, params.Encode()), nil
}

// TokenResponse represents the token endpoint response from KySignOn.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	IDToken      string `json:"id_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

// ExchangeCode exchanges an authorization code and PKCE verifier for a verified
// user profile. The ID token's signature, issuer, audience, expiry and nonce are
// all checked against the issuer's published JWKS before any session is created.
func (m *Manager) ExchangeCode(ctx context.Context, code, verifier, nonce string) (*UserInfo, error) {
	provider, err := m.oidcProvider(ctx)
	if err != nil {
		return nil, err
	}
	cfg := m.GetConfig()
	client := httpClient()

	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("redirect_uri", cfg.RedirectURL)
	data.Set("client_id", cfg.ClientID)
	data.Set("client_secret", cfg.ClientSecret)
	data.Set("code_verifier", verifier)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, provider.Endpoint().TokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed creating token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token exchange failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("token endpoint returned %d: %s", resp.StatusCode, string(body))
	}

	var tokResp TokenResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&tokResp); err != nil {
		return nil, fmt.Errorf("failed decoding token response: %w", err)
	}

	var userInfo *UserInfo
	if tokResp.IDToken != "" {
		// A present-but-invalid ID token is an authentication failure, never a
		// reason to fall back to an unverified profile source.
		userInfo, err = m.verifyIDToken(ctx, provider, tokResp.IDToken, nonce)
		if err != nil {
			return nil, err
		}
	} else {
		userInfo, err = m.fetchUserInfo(ctx, provider, tokResp.AccessToken)
		if err != nil {
			return nil, fmt.Errorf("issuer returned no id_token and userinfo failed: %w", err)
		}
	}

	// Assign role
	if cfg.AdminEmail != "" && strings.EqualFold(userInfo.Email, cfg.AdminEmail) {
		userInfo.Role = "admin"
	} else {
		userInfo.Role = NormalizeRole(userInfo.Role)
	}

	return userInfo, nil
}

// verifyIDToken validates the JWS and the standard OIDC claims, then extracts the profile.
func (m *Manager) verifyIDToken(ctx context.Context, provider *oidc.Provider, rawIDToken, nonce string) (*UserInfo, error) {
	verifier := provider.Verifier(&oidc.Config{ClientID: m.GetConfig().ClientID})
	idToken, err := verifier.Verify(oidc.ClientContext(ctx, httpClient()), rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("id_token verification failed: %w", err)
	}
	if nonce == "" || idToken.Nonce != nonce {
		return nil, errors.New("id_token nonce does not match this login attempt")
	}

	var claims struct {
		Email string   `json:"email"`
		Name  string   `json:"name"`
		Role  string   `json:"role"`
		Roles []string `json:"roles"`
	}
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("failed reading id_token claims: %w", err)
	}

	role := claims.Role
	if role == "" && len(claims.Roles) > 0 {
		role = claims.Roles[0]
	}

	return &UserInfo{
		Subject: idToken.Subject,
		Email:   claims.Email,
		Name:    claims.Name,
		Role:    role,
	}, nil
}

func (m *Manager) fetchUserInfo(ctx context.Context, provider *oidc.Provider, accessToken string) (*UserInfo, error) {
	if accessToken == "" {
		return nil, errors.New("no access token returned by issuer")
	}
	info, err := provider.UserInfo(oidc.ClientContext(ctx, httpClient()), oauth2.StaticTokenSource(&oauth2.Token{
		AccessToken: accessToken,
		TokenType:   "Bearer",
	}))
	if err != nil {
		return nil, err
	}

	var claims struct {
		Name string `json:"name"`
		Role string `json:"role"`
	}
	_ = info.Claims(&claims)

	return &UserInfo{
		Subject: info.Subject,
		Email:   info.Email,
		Name:    claims.Name,
		Role:    claims.Role,
	}, nil
}

// CreateSession registers a new authenticated session in SQLite and returns a session cookie.
// secure marks the cookie HTTPS-only; see server.cookieSecure for how that is decided.
func (m *Manager) CreateSession(ctx context.Context, u *UserInfo, secure bool) (*http.Cookie, error) {
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
		Secure:   secure,
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

// Roles understood by KyRecovery, from least to most privileged.
const (
	RoleViewer   = "viewer"
	RoleOperator = "operator"
	RoleAdmin    = "admin"
)

// NormalizeRole maps an identity provider's role claim onto a KyRecovery role.
// Anything unrecognised becomes the least privileged role rather than a guess.
func NormalizeRole(role string) string {
	switch strings.ToLower(strings.TrimSpace(role)) {
	case RoleAdmin:
		return RoleAdmin
	case RoleOperator:
		return RoleOperator
	default:
		return RoleViewer
	}
}

// RoleRank orders roles for authorization checks. Unknown roles rank below viewer.
func RoleRank(role string) int {
	switch strings.ToLower(strings.TrimSpace(role)) {
	case RoleAdmin:
		return 3
	case RoleOperator:
		return 2
	case RoleViewer:
		return 1
	default:
		return 0
	}
}
