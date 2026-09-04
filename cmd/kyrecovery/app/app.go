package app

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/Busness-app/kyrecovery-server/internal/audit"
	"github.com/Busness-app/kyrecovery-server/internal/auth"
	"github.com/Busness-app/kyrecovery-server/internal/db"
	"github.com/Busness-app/kyrecovery-server/internal/pairing"
	"github.com/Busness-app/kyrecovery-server/internal/server"
	"github.com/Busness-app/kyrecovery-server/pkg/client"
)

func Run(args []string) {
	if len(args) < 2 {
		printUsage()
		return
	}

	command := args[1]
	switch command {
	case "serve":
		cmdServe(args[2:])
	case "audit":
		cmdAudit(args[2:])
	case "pair":
		cmdPair(args[2:])
	case "help", "--help", "-h":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command %q. Run 'kyrecovery help' for usage.\n", command)
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`KyRecovery — Disaster Recovery & Verification Service for KySecurity

Usage:
  kyrecovery <command> [options]

Commands:
  serve           Start KyRecovery web dashboard and REST API daemon
  audit           Inspect or verify cryptographic audit log chain
  pair            Manage paired product connectors and ephemeral 6-digit codes

Run 'kyrecovery <command> --help' for details on each command.`)
}

// 1. Serve
func cmdServe(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	port := fs.Int("port", 8095, "HTTP server listener port")
	dataDir := fs.String("data-dir", "./data", "Directory for SQLite database and capsule storage")
	ssoIssuer := fs.String("sso-issuer", os.Getenv("KY_SSO_ISSUER"), "KySignOn OIDC Issuer URL (e.g. http://localhost:8080)")
	ssoClientID := fs.String("sso-client-id", os.Getenv("KY_SSO_CLIENT_ID"), "KySignOn OAuth Client ID")
	ssoClientSecret := fs.String("sso-client-secret", os.Getenv("KY_SSO_CLIENT_SECRET"), "KySignOn OAuth Client Secret")
	ssoRedirectURL := fs.String("sso-redirect-url", os.Getenv("KY_SSO_REDIRECT_URL"), "KySignOn OAuth Callback Redirect URL")
	ssoAdminEmail := fs.String("sso-admin-email", os.Getenv("KY_ADMIN_EMAIL"), "Admin user email address")
	cookieSecure := fs.String("cookie-secure", os.Getenv("KYRECOVERY_COOKIE_SECURE"), "Force the Secure flag on session cookies: true, false, or empty to follow the request transport")
	fs.Parse(args)

	var cookieSecureFlag *bool
	switch strings.ToLower(strings.TrimSpace(*cookieSecure)) {
	case "true", "1", "yes":
		v := true
		cookieSecureFlag = &v
	case "false", "0", "no":
		v := false
		cookieSecureFlag = &v
	case "":
	default:
		fmt.Fprintf(os.Stderr, "Invalid --cookie-secure value %q (expected true, false or empty)\n", *cookieSecure)
		os.Exit(1)
	}

	if err := os.MkdirAll(*dataDir, 0700); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create data directory: %v\n", err)
		os.Exit(1)
	}

	dbPath := filepath.Join(*dataDir, "kyrecovery.db")
	database, err := db.Open(dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Database initialization error: %v\n", err)
		os.Exit(1)
	}
	defer database.Close()

	if *ssoRedirectURL == "" && *ssoIssuer != "" {
		*ssoRedirectURL = fmt.Sprintf("http://localhost:%d/api/auth/callback", *port)
	}

	authCfg := auth.OIDCConfig{
		Enabled:      *ssoIssuer != "",
		IssuerURL:    *ssoIssuer,
		ClientID:     *ssoClientID,
		ClientSecret: *ssoClientSecret,
		RedirectURL:  *ssoRedirectURL,
		AdminEmail:   *ssoAdminEmail,
	}

	authMgr := auth.NewManager(authCfg, database)
	initPass := os.Getenv("KY_ADMIN_INITIAL_PASSWORD")
	adminPass, isNew, err := authMgr.EnsureAdminUser(context.Background(), initPass)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed ensuring admin user: %v\n", err)
	} else if isNew {
		fmt.Println("================================================================================")
		fmt.Println("🚀 KyRecovery Server First-Time Startup Initialized")
		fmt.Println("   Local Administrator Credentials:")
		fmt.Println("     Username: admin")
		fmt.Printf("     Password: %s\n", adminPass)
		fmt.Println("   Save this password securely or pair KySignOn SSO in the dashboard.")
		fmt.Println("================================================================================")
	}

	ledger := audit.NewLedger(database)
	srv, err := server.New(server.Config{
		Port:         *port,
		DataDir:      *dataDir,
		DatabasePath: dbPath,
		Auth:         authCfg,
		CookieSecure: cookieSecureFlag,
	}, database, ledger)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Server initialization error: %v\n", err)
		os.Exit(1)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	fmt.Printf("⚡ KyRecovery Server listening on http://0.0.0.0:%d (data: %s)\n", *port, *dataDir)
	if cookieSecureFlag == nil {
		fmt.Println("   Serving plain HTTP: sessions started over HTTP get cookies without the Secure flag.")
		fmt.Println("   Terminate TLS in front of KyRecovery (or set --cookie-secure=true) for production use.")
	}
	if err := srv.Start(ctx); err != nil && err != context.Canceled {
		fmt.Fprintf(os.Stderr, "Server error: %v\n", err)
		os.Exit(1)
	}
}

// 2. Audit
func cmdAudit(args []string) {
	if len(args) == 0 || args[0] != "verify" {
		fmt.Println("Usage: kyrecovery audit verify [--data-dir ./data]")
		return
	}

	fs := flag.NewFlagSet("audit verify", flag.ExitOnError)
	dataDir := fs.String("data-dir", "./data", "Data directory containing SQLite database")
	fs.Parse(args[1:])

	dbPath := filepath.Join(*dataDir, "kyrecovery.db")
	database, err := db.Open(dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed opening database: %v\n", err)
		os.Exit(1)
	}
	defer database.Close()

	ledger := audit.NewLedger(database)
	anchor, err := ledger.Verify(context.Background())
	if err != nil {
		fmt.Printf("✗ Audit Chain Broken: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("✓ Cryptographic Audit Chain Valid (%d events verified)\n", anchor.Count)
	fmt.Printf("  Latest Hash: %s\n", anchor.Hash)
}

// 3. Pair
func cmdPair(args []string) {
	if len(args) == 0 {
		fmt.Println(`Usage:
  kyrecovery pair generate [--ttl 15] [--service <name>] [--app <name>] [--data-dir ./data]
  kyrecovery pair list [--data-dir ./data]
  kyrecovery pair claim --server <url> --code <6-digit-code> --service <service> --app <app-name>`)
		return
	}

	action := args[0]
	switch action {
	case "generate":
		fs := flag.NewFlagSet("pair generate", flag.ExitOnError)
		ttl := fs.Int("ttl", 15, "Pairing code expiration in minutes")
		service := fs.String("service", "auto-declare", "Expected service name")
		app := fs.String("app", "Connected App", "Expected app name")
		dataDir := fs.String("data-dir", "./data", "Data directory")
		fs.Parse(args[1:])

		dbPath := filepath.Join(*dataDir, "kyrecovery.db")
		database, err := db.Open(dbPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed opening database: %v\n", err)
			os.Exit(1)
		}
		defer database.Close()

		rec, err := pairing.GeneratePairingCode(context.Background(), database, time.Duration(*ttl)*time.Minute, *service, *app)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed generating pairing code: %v\n", err)
			os.Exit(1)
		}

		fmt.Println("=== PAIRING CODE GENERATED ===")
		fmt.Printf("Pairing Code: %s\n", rec.PairingCode)
		fmt.Printf("Expires In:   %d minutes (%s)\n", *ttl, rec.ExpiresAt.Format("15:04:05 UTC"))
		fmt.Println("\nEnter this 6-digit code in your KySecurity / Business.app settings to establish automated backup sync.")

	case "list":
		fs := flag.NewFlagSet("pair list", flag.ExitOnError)
		dataDir := fs.String("data-dir", "./data", "Data directory")
		fs.Parse(args[1:])

		dbPath := filepath.Join(*dataDir, "kyrecovery.db")
		database, err := db.Open(dbPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed opening database: %v\n", err)
			os.Exit(1)
		}
		defer database.Close()

		list, err := database.ListPairedApps(context.Background())
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed listing paired apps: %v\n", err)
			os.Exit(1)
		}

		if len(list) == 0 {
			fmt.Println("No paired applications or active pairing codes found.")
			return
		}

		fmt.Println("=== PAIRED APPLICATIONS & CONNECTORS ===")
		for _, a := range list {
			fmt.Printf("- [%s] %s (%s) — Code: %s, Status: %s\n", a.ID, a.AppName, a.ServiceName, a.PairingCode, a.Status)
		}

	case "claim":
		fs := flag.NewFlagSet("pair claim", flag.ExitOnError)
		serverURL := fs.String("server", "http://localhost:8080", "KyRecovery server URL")
		code := fs.String("code", "", "6-digit pairing code")
		appName := fs.String("app", "KySecurity Client", "Client application name")
		fs.Parse(args[1:])

		if *code == "" {
			fmt.Fprintln(os.Stderr, "Error: --code is required")
			os.Exit(1)
		}

		_, resp, err := client.ClaimPairing(context.Background(), *serverURL, *code, *appName)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Claiming failed: %v\n", err)
			os.Exit(1)
		}

		fmt.Println("=== PAIRING SUCCESSFUL ===")
		fmt.Printf("App Name:     %s\n", resp.AppName)
		fmt.Printf("Service:      %s\n", resp.ServiceName)
		fmt.Printf("API Token:    %s\n", resp.APIToken)
		fmt.Println("\nSave this API Token in your service configuration to deposit sealed capsules.")

	default:
		fmt.Fprintf(os.Stderr, "Unknown pairing sub-action %q (valid: generate, list, claim)\n", action)
		os.Exit(1)
	}
}
