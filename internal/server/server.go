package server

import (
	"context"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/Busness-app/kyrecovery-server/internal/audit"
	"github.com/Busness-app/kyrecovery-server/internal/auth"
	"github.com/Busness-app/kyrecovery-server/internal/db"
	"github.com/Busness-app/kyrecovery-server/internal/diff"
	"github.com/Busness-app/kyrecovery-server/internal/pairing"
	"github.com/Busness-app/kyrecovery-server/internal/replication"
)

//go:embed static/*
var staticFS embed.FS

// Config contains server options.
type Config struct {
	Port         int
	DataDir      string
	DatabasePath string
	Auth         auth.OIDCConfig

	// CookieSecure forces the Secure attribute on session cookies. When nil the
	// server follows the transport the request actually arrived on.
	CookieSecure *bool
}

// Server provides the HTTP router, REST API, and static assets for KyRecovery.
type Server struct {
	cfg         Config
	db          *db.DB
	ledger      *audit.Ledger
	authMgr     *auth.Manager
	replication *replication.Manager
	inspector   *diff.Inspector
	claimLimit  *rateLimiter
	loginLimit  *rateLimiter
	pushLimit   *rateLimiter
	pushSlots   chan struct{}
	mux         *http.ServeMux
}

// New creates a new KyRecovery server instance.
func New(cfg Config, database *db.DB, ledger *audit.Ledger) (*Server, error) {
	if cfg.DataDir == "" {
		cfg.DataDir = "./data"
	}
	if err := os.MkdirAll(filepath.Join(cfg.DataDir, "capsules"), 0700); err != nil {
		return nil, fmt.Errorf("failed to create capsules directory: %w", err)
	}

	authMgr := auth.NewManager(cfg.Auth, database)
	replMgr := replication.NewManager(database, ledger)
	inspector := diff.NewInspector(database)

	s := &Server{
		cfg:         cfg,
		db:          database,
		ledger:      ledger,
		authMgr:     authMgr,
		replication: replMgr,
		inspector:   inspector,
		claimLimit:  newRateLimiter(claimWindow),
		loginLimit:  newRateLimiter(loginWindow),
		pushLimit:   newRateLimiter(pushWindow),
		pushSlots:   make(chan struct{}, maxConcurrentPushes),
		mux:         http.NewServeMux(),
	}

	s.routes()
	return s, nil
}

func (s *Server) routes() {
	// Static files
	staticSub, _ := fs.Sub(staticFS, "static")
	fileServer := http.FileServer(http.FS(staticSub))
	s.mux.Handle("/static/", http.StripPrefix("/static/", fileServer))

	// Web UI index
	s.mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		data, err := staticFS.ReadFile("static/index.html")
		if err != nil {
			http.Error(w, "Index not found", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(data)
	})

	// Favicon Routes
	faviconHandler := func(w http.ResponseWriter, r *http.Request) {
		data, err := staticFS.ReadFile("static/favicon.svg")
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "image/svg+xml")
		w.Header().Set("Cache-Control", "public, max-age=86400")
		w.Write(data)
	}
	s.mux.HandleFunc("/favicon.svg", faviconHandler)
	s.mux.HandleFunc("/favicon.ico", faviconHandler)

	// Auth & SSO Routes
	s.mux.HandleFunc("/api/auth/config", s.handleAuthConfig)
	s.mux.HandleFunc("/api/auth/login", s.handleAuthLogin)
	s.mux.HandleFunc("/api/auth/login/local", s.handleAuthLoginLocal)
	s.mux.HandleFunc("/api/auth/password", s.handleAuthPasswordChange)
	s.mux.HandleFunc("/api/auth/sso/config", s.handleSSOConfig)
	s.mux.HandleFunc("/api/auth/sso/test", s.handleSSOTest)
	s.mux.HandleFunc("/api/auth/callback", s.handleAuthCallback)
	s.mux.HandleFunc("/api/auth/me", s.handleAuthMe)
	s.mux.HandleFunc("/api/auth/logout", s.handleAuthLogout)

	// API Routes
	s.mux.HandleFunc("/api/readiness", s.handleReadiness)
	s.mux.HandleFunc("/api/capsules", s.handleCapsules)
	s.mux.HandleFunc("/api/capsules/", s.handleCapsuleDetail)
	s.mux.HandleFunc("/api/custodians", s.handleCustodians)
	s.mux.HandleFunc("/api/audit", s.handleAudit)
	s.mux.HandleFunc("/api/audit/verify", s.handleAuditVerify)
	s.mux.HandleFunc("/api/recovery-key", s.handleRecoveryKey)

	// Pairing Routes
	s.mux.HandleFunc("/api/pairing/generate", s.handlePairingGenerate)
	s.mux.HandleFunc("/api/pairing/list", s.handlePairingList)
	s.mux.HandleFunc("/api/pairing/revoke", s.handlePairingRevoke)
	s.mux.HandleFunc("/api/pairing/claim", s.handlePairingClaim)

	// Product deposit (bearer product token)
	s.mux.HandleFunc("/api/backup/deposit", s.handleDeposit)

	// Offsite Replication Routes
	s.mux.HandleFunc("/api/replication/targets", s.handleReplicationTargets)
	s.mux.HandleFunc("/api/replication/targets/test", s.handleReplicationTargetTest)
	s.mux.HandleFunc("/api/replication/targets/", s.handleReplicationTargetDelete)
	s.mux.HandleFunc("/api/replication/sync", s.handleReplicationSync)
	s.mux.HandleFunc("/api/replication/logs", s.handleReplicationLogs)

	// Snapshot Diff & Rollback Inspector Routes
	s.mux.HandleFunc("/api/capsules/diff", s.handleCapsuleDiff)
	s.mux.HandleFunc("/api/capsules/timeline", s.handleCapsuleTimeline)
}

// contentSecurityPolicy is the second line of defence behind escaping in the
// dashboard: even if a value reaches innerHTML unescaped, injected markup cannot
// load or reach anything off-origin.
//
// ponytail: 'unsafe-inline' for scripts is here only because the dashboard still
// wires buttons with inline onclick=. Move those to addEventListener and drop it.
const contentSecurityPolicy = "default-src 'self'; script-src 'self' 'unsafe-inline'; " +
	"style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; " +
	"form-action 'none'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"

// rolePublic marks a route reachable without a session: it is needed to sign in,
// or it carries its own credential (a pairing code or a product API token).
const rolePublic = ""

// apiPolicy is the authorization table for the REST API, keyed by "<METHOD> <path>"
// with "*" matching any method. Everything not listed defaults to admin, so a new
// route is closed until it is deliberately opened here.
var apiPolicy = map[string]string{
	"* /api/auth/config":       rolePublic,
	"* /api/auth/me":           rolePublic,
	"* /api/auth/login":        rolePublic,
	"* /api/auth/login/local":  rolePublic,
	"* /api/auth/callback":     rolePublic,
	"* /api/auth/logout":       rolePublic,
	"GET /api/auth/sso/config": rolePublic, // the sign-in page must know whether SSO is offered
	"* /api/pairing/claim":     rolePublic, // one-time pairing code
	"* /api/backup/deposit":    rolePublic, // product API token

	"* /api/auth/password":         auth.RoleViewer,
	"GET /api/readiness":           auth.RoleViewer,
	"GET /api/capsules":            auth.RoleViewer,
	"GET /api/capsules/diff":       auth.RoleViewer,
	"GET /api/capsules/timeline":   auth.RoleViewer,
	"GET /api/custodians":          auth.RoleViewer,
	"GET /api/audit":               auth.RoleViewer,
	"GET /api/recovery-key":        auth.RoleViewer,
	"GET /api/pairing/list":        auth.RoleViewer,
	"GET /api/replication/targets": auth.RoleViewer,
	"GET /api/replication/logs":    auth.RoleViewer,

	"POST /api/custodians":       auth.RoleOperator,
	"POST /api/audit/verify":     auth.RoleOperator,
	"POST /api/replication/sync": auth.RoleOperator,

	"POST /api/auth/sso/config":          auth.RoleAdmin,
	"POST /api/auth/sso/test":            auth.RoleAdmin,
	"POST /api/recovery-key":             auth.RoleAdmin,
	"POST /api/pairing/generate":         auth.RoleAdmin,
	"POST /api/pairing/revoke":           auth.RoleAdmin,
	"POST /api/replication/targets":      auth.RoleAdmin,
	"POST /api/replication/targets/test": auth.RoleAdmin,
}

// parseCapsulePath is the single interpretation of an "/api/capsules/<id>/<action>"
// URL. requiredRole and handleCapsuleDetail must never disagree about what a URL
// means, so they both read it through here rather than matching substrings.
func parseCapsulePath(urlPath string) (capsuleID, action string) {
	parts := strings.Split(strings.Trim(urlPath, "/"), "/")
	if len(parts) < 3 {
		return "", ""
	}
	if len(parts) >= 4 {
		return parts[2], parts[3]
	}
	return parts[2], ""
}

// requiredRole returns the minimum role needed for an API request.
func requiredRole(method, urlPath string) string {
	if role, ok := apiPolicy[method+" "+urlPath]; ok {
		return role
	}
	if role, ok := apiPolicy["* "+urlPath]; ok {
		return role
	}

	// Capsule sub-resources: reading metadata is a viewer action, taking the
	// sealed bytes off the server is not.
	if strings.HasPrefix(urlPath, "/api/capsules/") && method == http.MethodGet {
		switch _, action := parseCapsulePath(urlPath); action {
		case "download":
			return auth.RoleOperator
		default:
			return auth.RoleViewer
		}
	}
	return auth.RoleAdmin
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Security headers
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
	w.Header().Set("Content-Security-Policy", contentSecurityPolicy)
	if r.TLS != nil {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")
	}

	if strings.HasPrefix(r.URL.Path, "/api/") {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/json")
		r.Body = http.MaxBytesReader(w, r.Body, bodyLimit(r.URL.Path))

		// An API path must be spelled the way it is meant, so the policy lookup
		// below and the handler that runs afterwards cannot read the same URL
		// differently. path.Clean removes trailing slashes, dot segments and
		// repeated separators; anything it changes is rejected rather than guessed at.
		if path.Clean(r.URL.Path) != r.URL.Path {
			writeError(w, http.StatusBadRequest, "Bad Request: path is not canonical")
			return
		}

		if required := requiredRole(r.Method, r.URL.Path); required != rolePublic {
			session, err := s.authMgr.GetSession(r.Context(), r)
			if err != nil || session == nil {
				writeError(w, http.StatusUnauthorized, "Unauthorized: Authentication required")
				return
			}
			if auth.RoleRank(session.Role) < auth.RoleRank(required) {
				writeError(w, http.StatusForbidden, fmt.Sprintf("Forbidden: %s role required", required))
				return
			}
		}
	}

	s.mux.ServeHTTP(w, r)
}

// cookieSecure decides whether a session cookie may only travel over HTTPS.
// KYRECOVERY_COOKIE_SECURE pins the answer for deployments that terminate TLS
// somewhere KyRecovery cannot observe; otherwise the cookie is marked Secure
// whenever the login itself arrived over TLS, so a session established over
// HTTPS can never leak back out over plaintext HTTP.
func (s *Server) cookieSecure(r *http.Request) bool {
	if s.cfg.CookieSecure != nil {
		return *s.cfg.CookieSecure
	}
	if r.TLS != nil {
		return true
	}
	return strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

// actor names the authenticated identity behind a request for the audit ledger.
// A caller-supplied name is never used here: an attacker who could choose it
// could write any actor they liked into the record of what they did.
func (s *Server) actor(r *http.Request) string {
	session, err := s.authMgr.GetSession(r.Context(), r)
	if err != nil || session == nil {
		return "anonymous"
	}
	if session.Email != "" {
		return session.Email
	}
	if session.Name != "" {
		return session.Name
	}
	return session.UserID
}

func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// 1. Readiness Handler
func (s *Server) handleReadiness(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	capsules, _ := s.db.ListCapsules(ctx)
	custodians, _ := s.db.ListCustodians(ctx)

	// A blind store cannot open a capsule, so it cannot report a verified restore.
	// It reports only what it can see: how many sealed capsules it holds. The
	// verify sweep is what will attest their integrity.
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"capsule_count":   len(capsules),
		"custodian_count": len(custodians),
	})
}

// 2. Capsules List
func (s *Server) handleCapsules(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	list, err := s.db.ListCapsules(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, list)
}

// 4. Capsule Detail / Download
func (s *Server) handleCapsuleDetail(w http.ResponseWriter, r *http.Request) {
	capsuleID, action := parseCapsulePath(r.URL.Path)
	if capsuleID == "" {
		writeError(w, http.StatusBadRequest, "Invalid capsule URL")
		return
	}

	ctx := r.Context()
	capRec, err := s.db.GetCapsule(ctx, capsuleID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed reading capsule record")
		return
	}
	if capRec == nil {
		writeError(w, http.StatusNotFound, "Capsule not found")
		return
	}

	switch action {
	case "download":
		// A corrupt row is still downloadable for forensics; the header and the JSON
		// detail both carry the status so a caller cannot mistake it for intact.
		capsuleBytes, err := os.ReadFile(capRec.FilePath)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "Capsule file unreadable on disk")
			return
		}
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s.kycap", capsuleID))
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("X-Capsule-Digest", capRec.Digest)
		w.Header().Set("X-Capsule-Status", capRec.Status)
		w.Write(capsuleBytes)

	case "verify":
		s.handleCapsuleVerify(w, r, capRec)

	default:
		writeJSON(w, http.StatusOK, capRec)
	}
}

// 5. Custodians Handler
type custodianCreateRequest struct {
	Name  string `json:"name"`
	Email string `json:"email"`
}

func (s *Server) handleCustodians(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	switch r.Method {
	case http.MethodGet:
		list, err := s.db.ListCustodians(ctx)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, list)

	case http.MethodPost:
		var req custodianCreateRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" || req.Email == "" {
			writeError(w, http.StatusBadRequest, "Name and Email are required")
			return
		}

		rawFP := sha256.Sum256([]byte(fmt.Sprintf("%s:%s:%d", req.Name, req.Email, time.Now().UnixNano())))
		fingerprint := fmt.Sprintf("SHA256:%s", hex.EncodeToString(rawFP[:8]))
		custID := fmt.Sprintf("cust-%d", time.Now().UnixNano())

		custRec := db.CustodianRecord{
			ID:          custID,
			Name:        req.Name,
			Email:       req.Email,
			Fingerprint: fingerprint,
			CreatedAt:   time.Now().UTC(),
		}

		if err := s.db.InsertCustodian(ctx, custRec); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}

		_, _ = s.ledger.Record(ctx, "custodian_added", s.actor(r), custID, map[string]interface{}{
			"name":        req.Name,
			"email":       req.Email,
			"fingerprint": fingerprint,
		})

		writeJSON(w, http.StatusOK, custRec)

	default:
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

// 8. Audit List
func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	events, err := s.db.ListAuditEvents(r.Context(), 100)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, events)
}

// 9. Audit Chain Verification
func (s *Server) handleAuditVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	anchor, err := s.ledger.Verify(r.Context())
	resp := map[string]interface{}{
		"valid":     err == nil,
		"count":     anchor.Count,
		"last_hash": anchor.Hash,
	}
	if err != nil {
		resp["error"] = err.Error()
	}
	writeJSON(w, http.StatusOK, resp)
}

// 10. Pairing Generate
type pairingGenRequest struct {
	TTLMinutes  int    `json:"ttl_minutes"`
	ServiceName string `json:"service_name"`
	AppName     string `json:"app_name"`
}

func (s *Server) handlePairingGenerate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var req pairingGenRequest
	_ = json.NewDecoder(r.Body).Decode(&req)

	ttl := 15 * time.Minute
	if req.TTLMinutes > 0 {
		ttl = time.Duration(req.TTLMinutes) * time.Minute
	}
	// A six-digit code is only as strong as the window it is guessable in.
	if ttl > maxPairingTTL {
		writeError(w, http.StatusBadRequest,
			fmt.Sprintf("ttl_minutes cannot exceed %d", int(maxPairingTTL.Minutes())))
		return
	}

	record, err := pairing.GeneratePairingCode(r.Context(), s.db, ttl, req.ServiceName, req.AppName)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("Failed generating pairing code: %v", err))
		return
	}

	_, _ = s.ledger.Record(r.Context(), "pairing_code_generated", s.actor(r), record.ID, map[string]interface{}{
		"expires_at": record.ExpiresAt,
	})

	// The record also carries the API token, which belongs to the product that
	// claims the code, not to the administrator who generated it.
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"id":           record.ID,
		"service_name": record.ServiceName,
		"app_name":     record.AppName,
		"pairing_code": record.PairingCode,
		"status":       record.Status,
		"expires_at":   record.ExpiresAt,
		"created_at":   record.CreatedAt,
	})
}

// 11. Pairing List
func (s *Server) handlePairingList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	list, err := s.db.ListPairedApps(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, list)
}

// 12. Pairing Revoke
type pairingRevokeRequest struct {
	ID string `json:"id"`
}

func (s *Server) handlePairingRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	var req pairingRevokeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ID == "" {
		writeError(w, http.StatusBadRequest, "ID is required")
		return
	}
	if err := s.db.RevokePairedApp(r.Context(), req.ID); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_, _ = s.ledger.Record(r.Context(), "pairing_token_revoked", s.actor(r), req.ID, nil)
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}

// 13. Pairing Claim
type pairingClaimRequest struct {
	PairingCode string `json:"pairing_code"`
	ServiceName string `json:"service_name"`
	AppName     string `json:"app_name"`
}

func (s *Server) handlePairingClaim(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	now := time.Now()
	ipKey := "ip:" + clientIP(r)
	if s.claimLimit.exceeded(ipKey, claimAttemptsPerIP, now) {
		writeError(w, http.StatusTooManyRequests, "Too many pairing attempts from this address")
		return
	}

	var req pairingClaimRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.PairingCode == "" {
		s.claimLimit.record(ipKey, now)
		writeError(w, http.StatusBadRequest, "PairingCode is required")
		return
	}
	codeKey := "code:" + req.PairingCode
	if s.claimLimit.exceeded(codeKey, claimAttemptsPerCode, now) {
		writeError(w, http.StatusTooManyRequests, "Too many attempts for this pairing code")
		return
	}
	if req.ServiceName == "" {
		req.ServiceName = "generic"
	}
	if req.AppName == "" {
		req.AppName = fmt.Sprintf("App-%s", req.PairingCode)
	}

	key, err := s.db.GetRecoveryKey(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed reading recovery key")
		return
	}
	if key == nil {
		// Not a failed attempt by the product: the store is not ready. The code is not consumed
		// and the limiter is not charged.
		writeError(w, http.StatusConflict, "No recovery key imported; run the ceremony before pairing products")
		return
	}

	app, err := s.db.ClaimPairingCode(r.Context(), req.PairingCode, req.ServiceName, req.AppName, key.KeyID)
	if err != nil {
		s.claimLimit.record(ipKey, now)
		s.claimLimit.record(codeKey, now)
		status := http.StatusBadRequest
		if strings.Contains(err.Error(), "already consumed") {
			status = http.StatusConflict
		}
		writeError(w, status, err.Error())
		return
	}

	_, _ = s.ledger.Record(r.Context(), "product_paired", "pairing-code:"+app.ID, app.ID, map[string]interface{}{
		"service_name":     app.ServiceName,
		"claimed_app_name": app.AppName,
		"source_address":   clientIP(r),
		"recovery_key_id":  key.KeyID,
	})

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"id":                  app.ID,
		"status":              "paired",
		"api_token":           app.APIToken,
		"service_name":        app.ServiceName,
		"app_name":            app.AppName,
		"paired_at":           app.PairedAt,
		"server_url":          r.Host,
		"recovery_public_key": base64.StdEncoding.EncodeToString(key.PublicKey),
		"threshold":           key.Threshold,
		"total_shares":        key.TotalShares,
	})
}

// 15. Auth Config (Public status)
func (s *Server) handleAuthConfig(w http.ResponseWriter, r *http.Request) {
	cfg := s.authMgr.GetConfig()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"sso_enabled": s.authMgr.IsEnabled(),
		"issuer_url":  cfg.IssuerURL,
		"client_id":   cfg.ClientID,
	})
}

// 16. Auth Login (Initiates KySignOn OIDC PKCE Flow)
func (s *Server) handleAuthLogin(w http.ResponseWriter, r *http.Request) {
	if !s.authMgr.IsEnabled() {
		writeError(w, http.StatusBadRequest, "KySignOn SSO is not configured or enabled on this server. Please sign in as Local Admin.")
		return
	}

	verifier, challenge, err := auth.GeneratePKCE()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed generating PKCE challenge")
		return
	}
	state, _ := auth.GenerateRandomString(16)
	nonce, _ := auth.GenerateRandomString(16)

	http.SetCookie(w, &http.Cookie{
		Name:     "kyrec_pkce",
		Value:    verifier,
		Path:     "/api/auth/callback",
		Expires:  time.Now().Add(10 * time.Minute),
		HttpOnly: true,
		Secure:   s.cookieSecure(r),
		SameSite: http.SameSiteLaxMode,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     "kyrec_state",
		Value:    state,
		Path:     "/api/auth/callback",
		Expires:  time.Now().Add(10 * time.Minute),
		HttpOnly: true,
		Secure:   s.cookieSecure(r),
		SameSite: http.SameSiteLaxMode,
	})
	// The nonce is bound to this browser so the ID token returned at the callback
	// can be proven to belong to this login attempt.
	http.SetCookie(w, &http.Cookie{
		Name:     "kyrec_nonce",
		Value:    nonce,
		Path:     "/api/auth/callback",
		Expires:  time.Now().Add(10 * time.Minute),
		HttpOnly: true,
		Secure:   s.cookieSecure(r),
		SameSite: http.SameSiteLaxMode,
	})

	authURL, err := s.authMgr.BuildAuthURL(r.Context(), state, nonce, challenge)
	if err != nil {
		writeError(w, http.StatusBadGateway, fmt.Sprintf("KySignOn discovery failed: %v", err))
		return
	}
	http.Redirect(w, r, authURL, http.StatusFound)
}

// 16b. Local Admin Login
type localLoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (s *Server) handleAuthLoginLocal(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var req localLoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid JSON login payload")
		return
	}

	// Argon2id makes each guess expensive for the server as well as the attacker,
	// so unauthenticated login attempts are capped per source address and per account.
	now := time.Now()
	ipKey := "login-ip:" + clientIP(r)
	accKey := "login-user:" + strings.ToLower(strings.TrimSpace(req.Username))
	if s.loginLimit.exceeded(ipKey, loginAttemptsPerIP, now) || s.loginLimit.exceeded(accKey, loginAttemptsPerAcc, now) {
		writeError(w, http.StatusTooManyRequests, "Too many failed sign-in attempts; try again later")
		return
	}

	userInfo, err := s.authMgr.AuthenticateLocal(r.Context(), req.Username, req.Password)
	if err != nil {
		s.loginLimit.record(ipKey, now)
		s.loginLimit.record(accKey, now)
		_, _ = s.ledger.Record(r.Context(), "user_login_failed", "anonymous", clientIP(r),
			map[string]interface{}{"claimed_username": req.Username})
		writeError(w, http.StatusUnauthorized, err.Error())
		return
	}

	sessionCookie, err := s.authMgr.CreateSession(r.Context(), userInfo, s.cookieSecure(r))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed creating session")
		return
	}

	http.SetCookie(w, sessionCookie)

	_, _ = s.ledger.Record(r.Context(), "user_logged_in_local", userInfo.Email, userInfo.Subject, map[string]interface{}{
		"username": req.Username,
		"role":     userInfo.Role,
	})

	// The session lives in an HttpOnly cookie only; echoing it into the response
	// body would hand it to any script that can read a fetch result.
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status": "authenticated",
		"user":   userInfo,
	})
}

// 16c. Change Admin / User Password
type passwordChangeRequest struct {
	OldPassword string `json:"old_password"`
	NewPassword string `json:"new_password"`
}

func (s *Server) handleAuthPasswordChange(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	session, err := s.authMgr.GetSession(r.Context(), r)
	if err != nil || session == nil {
		writeError(w, http.StatusUnauthorized, "Authentication required")
		return
	}

	var req passwordChangeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || len(req.NewPassword) < 8 {
		writeError(w, http.StatusBadRequest, "New password must be at least 8 characters long")
		return
	}

	// Verify old password
	user, err := s.db.GetUserByID(r.Context(), session.UserID)
	if err != nil || user == nil {
		writeError(w, http.StatusBadRequest, "User account not found")
		return
	}

	if !auth.VerifyPassword(req.OldPassword, user.PasswordHash, user.Salt) {
		writeError(w, http.StatusUnauthorized, "Current password is incorrect")
		return
	}

	newHash, newSalt, err := auth.HashPassword(req.NewPassword)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed hashing new password")
		return
	}

	if err := s.db.UpdateUserPassword(r.Context(), user.ID, newHash, newSalt); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed updating password")
		return
	}

	// Anyone signed in with the old password loses their session; the caller keeps
	// the one they are changing it from.
	if err := s.db.DeleteUserSessionsExcept(r.Context(), user.ID, session.ID); err != nil {
		audit.Log().Error("session_revoke", session.Email, user.ID, "failed revoking other sessions", err)
	}

	_, _ = s.ledger.Record(r.Context(), "password_changed", user.Email, user.ID, nil)

	writeJSON(w, http.StatusOK, map[string]string{"status": "password_updated"})
}

// 16d. SSO Pairing & Config Management (Admin)
func (s *Server) handleSSOConfig(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	switch r.Method {
	case http.MethodGet:
		cfg := s.authMgr.GetConfig()
		resp := map[string]interface{}{
			"enabled":    cfg.Enabled,
			"issuer_url": cfg.IssuerURL,
			"client_id":  cfg.ClientID,
		}
		// This route is reachable from the sign-in page, so the rest of the
		// configuration is only filled in for an administrator.
		if session, _ := s.authMgr.GetSession(ctx, r); session != nil && session.Role == auth.RoleAdmin {
			clientSecretMasked := ""
			if cfg.ClientSecret != "" {
				clientSecretMasked = "••••••••"
			}
			resp["client_secret"] = clientSecretMasked
			resp["redirect_url"] = cfg.RedirectURL
			resp["admin_email"] = cfg.AdminEmail
		}
		writeJSON(w, http.StatusOK, resp)

	case http.MethodPost:
		session, err := s.authMgr.GetSession(ctx, r)
		if err != nil || session == nil || session.Role != "admin" {
			writeError(w, http.StatusForbidden, "Admin role required to configure SSO settings")
			return
		}

		var req auth.OIDCConfig
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "Invalid JSON SSO config payload")
			return
		}

		if req.RedirectURL == "" && req.IssuerURL != "" {
			req.RedirectURL = fmt.Sprintf("http://%s/api/auth/callback", r.Host)
		}

		if err := s.authMgr.SaveConfig(ctx, req); err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Sprintf("Failed saving SSO config: %v", err))
			return
		}

		_, _ = s.ledger.Record(ctx, "sso_config_updated", session.Email, "sso_settings", map[string]interface{}{
			"enabled":    req.Enabled,
			"issuer_url": req.IssuerURL,
			"client_id":  req.ClientID,
		})

		writeJSON(w, http.StatusOK, map[string]interface{}{
			"status":  "saved",
			"config":  s.authMgr.GetConfig(),
			"enabled": s.authMgr.IsEnabled(),
		})

	default:
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

// 16e. Test KySignOn SSO Endpoint
type ssoTestRequest struct {
	IssuerURL string `json:"issuer_url"`
}

func (s *Server) handleSSOTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var req ssoTestRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.IssuerURL == "" {
		writeError(w, http.StatusBadRequest, "Issuer URL is required")
		return
	}

	if err := s.authMgr.TestSSOConnection(r.Context(), req.IssuerURL); err != nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"success": false,
			"error":   err.Error(),
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": fmt.Sprintf("Successfully connected to KySignOn authority at %s", req.IssuerURL),
	})
}

// 17. Auth Callback (Handles OIDC Authorization Code)
func (s *Server) handleAuthCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")

	stateCookie, err := r.Cookie("kyrec_state")
	if err != nil || stateCookie.Value != state || state == "" {
		writeError(w, http.StatusBadRequest, "Invalid or expired OAuth state parameter")
		return
	}

	pkceCookie, err := r.Cookie("kyrec_pkce")
	if err != nil || pkceCookie.Value == "" {
		writeError(w, http.StatusBadRequest, "Missing PKCE verifier cookie")
		return
	}

	nonceCookie, err := r.Cookie("kyrec_nonce")
	if err != nil || nonceCookie.Value == "" {
		writeError(w, http.StatusBadRequest, "Missing OIDC nonce cookie")
		return
	}

	userInfo, err := s.authMgr.ExchangeCode(r.Context(), code, pkceCookie.Value, nonceCookie.Value)
	if err != nil {
		writeError(w, http.StatusUnauthorized, fmt.Sprintf("Authentication failed: %v", err))
		return
	}

	sessionCookie, err := s.authMgr.CreateSession(r.Context(), userInfo, s.cookieSecure(r))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed creating session")
		return
	}

	http.SetCookie(w, sessionCookie)

	// Clean up temporary auth cookies
	http.SetCookie(w, &http.Cookie{Name: "kyrec_pkce", Value: "", Path: "/api/auth/callback", MaxAge: -1})
	http.SetCookie(w, &http.Cookie{Name: "kyrec_state", Value: "", Path: "/api/auth/callback", MaxAge: -1})
	http.SetCookie(w, &http.Cookie{Name: "kyrec_nonce", Value: "", Path: "/api/auth/callback", MaxAge: -1})

	_, _ = s.ledger.Record(r.Context(), "user_logged_in_sso", userInfo.Email, userInfo.Subject, map[string]interface{}{
		"name": userInfo.Name,
		"role": userInfo.Role,
	})

	http.Redirect(w, r, "/", http.StatusFound)
}

// 18. Auth Me (Current User)
func (s *Server) handleAuthMe(w http.ResponseWriter, r *http.Request) {
	session, err := s.authMgr.GetSession(r.Context(), r)
	if err != nil || session == nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"authenticated": false,
			"sso_enabled":   s.authMgr.IsEnabled(),
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"authenticated": true,
		"sso_enabled":   s.authMgr.IsEnabled(),
		"user": map[string]interface{}{
			"user_id":    session.UserID,
			"email":      session.Email,
			"name":       session.Name,
			"role":       session.Role,
			"expires_at": session.ExpiresAt,
		},
	})
}

// 19. Auth Logout
func (s *Server) handleAuthLogout(w http.ResponseWriter, r *http.Request) {
	clearCookie := s.authMgr.InvalidateSession(r.Context(), r)
	http.SetCookie(w, clearCookie)
	writeJSON(w, http.StatusOK, map[string]string{"status": "logged_out"})
}

// 25. Replication Targets List / Create
func (s *Server) handleReplicationTargets(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	switch r.Method {
	case http.MethodGet:
		targets, err := s.db.ListReplicationTargets(ctx)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		// Mask secret keys in list response
		for i := range targets {
			if targets[i].SecretKey != "" {
				targets[i].SecretKey = "••••••••"
			}
		}
		writeJSON(w, http.StatusOK, targets)

	case http.MethodPost:
		var target db.ReplicationTargetRecord
		if err := json.NewDecoder(r.Body).Decode(&target); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if target.ID == "" {
			target.ID = fmt.Sprintf("target-%s-%d", target.Type, time.Now().Unix())
		}
		if target.Name == "" {
			target.Name = "Offsite Target"
		}
		if target.Type == "" {
			target.Type = "s3"
		}
		if target.Region == "" {
			target.Region = "us-east-1"
		}
		if target.Prefix == "" {
			target.Prefix = "capsules/"
		}
		if target.Status == "" {
			target.Status = "active"
		}
		target.CreatedAt = time.Now().UTC()

		if err := s.db.InsertReplicationTarget(ctx, target); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}

		_, _ = s.ledger.Record(ctx, "replication_target_saved", s.actor(r), target.ID, map[string]interface{}{
			"name":      target.Name,
			"type":      target.Type,
			"endpoint":  target.Endpoint,
			"auto_sync": target.AutoSync,
		})

		target.SecretKey = "••••••••"
		writeJSON(w, http.StatusOK, target)

	default:
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

// 26. Replication Target Connection Test
func (s *Server) handleReplicationTargetTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	var target db.ReplicationTargetRecord
	if err := json.NewDecoder(r.Body).Decode(&target); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.replication.TestTarget(r.Context(), target); err != nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"success": false,
			"error":   err.Error(),
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Connection and write test successful",
	})
}

// 27. Replication Target Delete
func (s *Server) handleReplicationTargetDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete && r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	targetID := strings.TrimPrefix(r.URL.Path, "/api/replication/targets/")
	if targetID == "" {
		writeError(w, http.StatusBadRequest, "Target ID is required")
		return
	}
	if err := s.db.DeleteReplicationTarget(r.Context(), targetID); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_, _ = s.ledger.Record(r.Context(), "replication_target_deleted", s.actor(r), targetID, nil)
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// 28. Replication Manual Sync
type replSyncRequest struct {
	CapsuleID string `json:"capsule_id"`
	TargetID  string `json:"target_id"`
}

func (s *Server) handleReplicationSync(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	var req replSyncRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.CapsuleID == "" {
		writeError(w, http.StatusBadRequest, "CapsuleID is required")
		return
	}

	ctx := r.Context()
	if req.TargetID != "" {
		logRec, err := s.replication.SyncCapsule(ctx, req.CapsuleID, req.TargetID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Sprintf("Replication failed: %v", err))
			return
		}
		writeJSON(w, http.StatusOK, logRec)
		return
	}

	// Sync to all auto targets
	logs := s.replication.SyncAllAutoTargets(ctx, req.CapsuleID)
	writeJSON(w, http.StatusOK, logs)
}

// 29. Replication Logs
func (s *Server) handleReplicationLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	logs, err := s.db.ListReplicationLogs(r.Context(), 50)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, logs)
}

// 30. Capsule Version Diff
func (s *Server) handleCapsuleDiff(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	baseID := r.URL.Query().Get("base")
	targetID := r.URL.Query().Get("target")

	if baseID == "" || targetID == "" {
		writeError(w, http.StatusBadRequest, "Both 'base' and 'target' capsule IDs are required")
		return
	}

	report, err := s.inspector.DiffByCapsuleIDs(r.Context(), baseID, targetID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, report)
}

// 31. Service Snapshot Timeline
func (s *Server) handleCapsuleTimeline(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	service := r.URL.Query().Get("service")
	timeline, err := s.inspector.GetServiceTimeline(r.Context(), service)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, timeline)
}

// Start runs the HTTP listener until context cancellation.
func (s *Server) Start(ctx context.Context) error {
	addr := fmt.Sprintf(":%d", s.cfg.Port)
	srv := &http.Server{
		Addr:         addr,
		Handler:      s,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	go s.runIntegritySweep(ctx)

	errChan := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errChan <- err
		}
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		s.Close()
		return srv.Shutdown(shutdownCtx)
	case err := <-errChan:
		s.Close()
		return err
	}
}

// Close releases background workers owned by the server. Nothing owns one today —
// the ceremony manager that did is gone — but Start still calls it on shutdown, so
// the hook stays rather than being reintroduced by whatever acquires one next.
func (s *Server) Close() {}
