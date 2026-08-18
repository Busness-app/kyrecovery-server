package app

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"kyrecovery-server/internal/adapter"
	"kyrecovery-server/internal/audit"
	"kyrecovery-server/internal/auth"
	"kyrecovery-server/internal/capsule"
	"kyrecovery-server/internal/crypto"
	"kyrecovery-server/internal/db"
	"kyrecovery-server/internal/drill"
	"kyrecovery-server/internal/export"
	"kyrecovery-server/internal/pairing"
	"kyrecovery-server/internal/server"
	"kyrecovery-server/internal/tui"
	"kyrecovery-server/pkg/client"
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
	case "capture":
		cmdCapture(args[2:])
	case "restore":
		cmdRestore(args[2:])
	case "drill":
		cmdDrill(args[2:])
	case "split-key":
		cmdSplitKey(args[2:])
	case "combine-shares":
		cmdCombineShares(args[2:])
	case "export-kit":
		cmdExportKit(args[2:])
	case "audit":
		cmdAudit(args[2:])
	case "pair":
		cmdPair(args[2:])
	case "tui":
		cmdTUI(args[2:])
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
  tui             Launch air-gapped interactive disaster recovery terminal console
  capture         Capture and encrypt a recovery capsule from a service
  restore         Decrypt and restore capsule contents into destination directory
  drill           Execute an isolated, ephemeral restore verification drill
  split-key       Generate Shamir's Secret Sharing threshold shares for a key
  combine-shares  Reconstruct master encryption key from threshold shares
  export-kit      Generate human-readable emergency disaster recovery runbook (HTML/MD)
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
	fs.Parse(args)

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
	}, database, ledger)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Server initialization error: %v\n", err)
		os.Exit(1)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	fmt.Printf("⚡ KyRecovery Server listening on http://0.0.0.0:%d (data: %s)\n", *port, *dataDir)
	if err := srv.Start(ctx); err != nil && err != context.Canceled {
		fmt.Fprintf(os.Stderr, "Server error: %v\n", err)
		os.Exit(1)
	}
}

// 2. Capture
func cmdCapture(args []string) {
	fs := flag.NewFlagSet("capture", flag.ExitOnError)
	serviceName := fs.String("service", "kysignon", "Target service name (kysignon)")
	sourceDir := fs.String("source-dir", "", "Path to service data directory")
	outPath := fs.String("out", "", "Output path for .kycap file (default: ./<capsule-id>.kycap)")
	threshold := fs.Int("threshold", 2, "Shamir quorum threshold (M)")
	shares := fs.Int("shares", 3, "Total Shamir shares (N)")
	fs.Parse(args)

	adapters := map[string]adapter.ServiceAdapter{
		"kysignon":   adapter.NewKySignOnAdapter(),
		"kypassword": adapter.NewKyPasswordAdapter(),
		"generic":    adapter.NewGenericAdapter(),
	}

	adp, exists := adapters[*serviceName]
	if !exists {
		fmt.Fprintf(os.Stderr, "Unsupported service adapter %q (supported: kysignon, kypassword, generic)\n", *serviceName)
		os.Exit(1)
	}

	ctx := context.Background()
	files, deps, err := adp.Capture(ctx, *sourceDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Capture failed: %v\n", err)
		os.Exit(1)
	}

	res, err := capsule.Pack(capsule.PackOptions{
		ServiceName:  *serviceName,
		Files:        files,
		Dependencies: deps,
		Threshold:    *threshold,
		TotalShares:  *shares,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Capsule packing failed: %v\n", err)
		os.Exit(1)
	}

	dest := *outPath
	if dest == "" {
		dest = fmt.Sprintf("%s.kycap", res.Manifest.CapsuleID)
	}

	if err := os.WriteFile(dest, res.CapsuleBytes, 0600); err != nil {
		fmt.Fprintf(os.Stderr, "Failed saving capsule to %s: %v\n", dest, err)
		os.Exit(1)
	}

	fmt.Printf("✓ Capsule created: %s (Size: %d bytes)\n", dest, len(res.CapsuleBytes))
	fmt.Printf("  Capsule ID:   %s\n", res.Manifest.CapsuleID)
	fmt.Printf("  Payload SHA:  %s\n", res.Manifest.PayloadHash)
	fmt.Printf("  Quorum:       %d of %d shares\n\n", res.Manifest.Threshold, res.Manifest.TotalShares)
	fmt.Println("--- Custodian Secret Shares (DISTRIBUTE SAFELY, NEVER COMMITTED) ---")
	for _, sh := range res.Shares {
		fmt.Println(sh.String())
	}
}

// 3. Restore
func cmdRestore(args []string) {
	fs := flag.NewFlagSet("restore", flag.ExitOnError)
	capsulePath := fs.String("capsule", "", "Path to .kycap capsule file")
	keyHex := fs.String("key", "", "Master encryption key (hex)")
	rawShares := fs.String("shares", "", "Comma-separated custodian shares (format: 1-hex,2-hex)")
	targetDir := fs.String("target", "", "Target destination directory")
	fs.Parse(args)

	if *capsulePath == "" || *targetDir == "" {
		fmt.Fprintln(os.Stderr, "Error: --capsule and --target are required")
		os.Exit(1)
	}

	manifest, err := capsule.ReadManifestFromFile(*capsulePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed parsing manifest from %s: %v\n", *capsulePath, err)
		os.Exit(1)
	}

	var key []byte
	if *keyHex != "" {
		key, err = hex.DecodeString(*keyHex)
		if err != nil || len(key) != crypto.KeyLength {
			fmt.Fprintf(os.Stderr, "Invalid key hex format: %v\n", err)
			os.Exit(1)
		}
	} else if *rawShares != "" {
		var shareList []crypto.Share
		for _, s := range strings.Split(*rawShares, ",") {
			sh, err := crypto.ParseShare(s)
			if err == nil {
				shareList = append(shareList, sh)
			}
		}
		key, err = crypto.Combine(shareList, manifest.Threshold)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed reconstructing key from shares: %v\n", err)
			os.Exit(1)
		}
	} else {
		fmt.Fprintln(os.Stderr, "Error: either --key or --shares must be provided")
		os.Exit(1)
	}

	// Constant O(1) memory streaming restore
	_, err = capsule.UnpackToDirectoryStream(*capsulePath, key, *targetDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Streaming restore failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("✓ Successfully restored capsule %s into %s (Streaming O(1) RAM)\n", manifest.CapsuleID, *targetDir)
}

// 4. Drill
func cmdDrill(args []string) {
	fs := flag.NewFlagSet("drill", flag.ExitOnError)
	capsulePath := fs.String("capsule", "", "Path to .kycap capsule file")
	keyHex := fs.String("key", "", "Master encryption key (hex)")
	rawShares := fs.String("shares", "", "Comma-separated custodian shares")
	fs.Parse(args)

	if *capsulePath == "" {
		fmt.Fprintln(os.Stderr, "Error: --capsule is required")
		os.Exit(1)
	}

	ssoAdapter := adapter.NewKySignOnAdapter()
	pwdAdapter := adapter.NewKyPasswordAdapter()
	bkmAdapter := adapter.NewKyBookmarksAdapter()
	notesAdapter := adapter.NewKyNotesAdapter()
	postAdapter := adapter.NewKyPostAdapter()
	genericAdapter := adapter.NewGenericAdapter()
	runner := drill.NewRunner(nil, nil, ssoAdapter, pwdAdapter, bkmAdapter, notesAdapter, postAdapter, genericAdapter)

	var key []byte
	var shareList []crypto.Share
	if *keyHex != "" {
		key, _ = hex.DecodeString(*keyHex)
	} else if *rawShares != "" {
		for _, s := range strings.Split(*rawShares, ",") {
			if sh, err := crypto.ParseShare(s); err == nil {
				shareList = append(shareList, sh)
			}
		}
	}

	summary, err := runner.Execute(context.Background(), drill.DrillParams{
		CapsulePath: *capsulePath,
		MasterKey:   key,
		Shares:      shareList,
		Actor:       "cli-operator",
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Drill failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("=== EPHEMERAL RESTORE DRILL REPORT ===")
	fmt.Printf("Drill ID:    %s\n", summary.DrillID)
	fmt.Printf("Capsule ID:  %s\n", summary.CapsuleID)
	fmt.Printf("Service:     %s\n", summary.ServiceName)
	fmt.Printf("Result:      %s\n", strings.ToUpper(fmt.Sprintf("%v", summary.Passed)))
	fmt.Printf("Duration:    %d ms (RTO)\n", summary.DurationMs)
	fmt.Println("\nVerification Checks:")
	for _, c := range summary.Checks {
		tag := "[PASS]"
		if !c.Passed {
			tag = "[FAIL]"
		}
		fmt.Printf("  %s %s: %s\n", tag, c.Name, c.Message)
	}

	if !summary.Passed {
		os.Exit(1)
	}
}

// 5. Split Key
func cmdSplitKey(args []string) {
	fs := flag.NewFlagSet("split-key", flag.ExitOnError)
	keyHex := fs.String("key", "", "Master key in hex (leave empty to generate a new 256-bit key)")
	threshold := fs.Int("threshold", 3, "Threshold (M)")
	total := fs.Int("shares", 5, "Total shares (N)")
	fs.Parse(args)

	var key []byte
	var err error
	if *keyHex != "" {
		key, err = hex.DecodeString(*keyHex)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Invalid key hex: %v\n", err)
			os.Exit(1)
		}
	} else {
		key, err = crypto.GenerateMasterKey()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed generating key: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Generated 256-bit Master Key: %s\n\n", hex.EncodeToString(key))
	}

	shares, err := crypto.Split(key, *threshold, *total)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Split failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Shamir's Secret Sharing (%d of %d):\n", *threshold, *total)
	for _, s := range shares {
		fmt.Println(s.String())
	}
}

// 6. Combine Shares
func cmdCombineShares(args []string) {
	fs := flag.NewFlagSet("combine-shares", flag.ExitOnError)
	threshold := fs.Int("threshold", 2, "Threshold (M)")
	rawShares := fs.String("shares", "", "Comma-separated shares (1-hex,2-hex)")
	fs.Parse(args)

	if *rawShares == "" {
		fmt.Fprintln(os.Stderr, "Error: --shares is required")
		os.Exit(1)
	}

	var shares []crypto.Share
	for _, s := range strings.Split(*rawShares, ",") {
		sh, err := crypto.ParseShare(s)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Invalid share %q: %v\n", s, err)
			os.Exit(1)
		}
		shares = append(shares, sh)
	}

	key, err := crypto.Combine(shares, *threshold)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed combining shares: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("✓ Successfully reconstructed master key: %s\n", hex.EncodeToString(key))
}

// 7. Export Kit
func cmdExportKit(args []string) {
	fs := flag.NewFlagSet("export-kit", flag.ExitOnError)
	capsulePath := fs.String("capsule", "", "Path to .kycap capsule file")
	format := fs.String("format", "html", "Export format: html or md")
	outPath := fs.String("out", "", "Output file path (default: stdout or runbook.html)")
	fs.Parse(args)

	if *capsulePath == "" {
		fmt.Fprintln(os.Stderr, "Error: --capsule is required")
		os.Exit(1)
	}

	capsuleBytes, err := os.ReadFile(*capsulePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed reading capsule: %v\n", err)
		os.Exit(1)
	}

	manifest, err := capsule.ReadManifest(capsuleBytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed parsing manifest: %v\n", err)
		os.Exit(1)
	}

	kitData := export.KitData{
		CapsuleID:    manifest.CapsuleID,
		ServiceName:  manifest.ServiceName,
		GeneratedAt:  manifest.CreatedAt,
		Threshold:    manifest.Threshold,
		TotalShares:  manifest.TotalShares,
		PayloadHash:  manifest.PayloadHash,
		Dependencies: manifest.Dependencies,
		Files:        manifest.Files,
	}

	var output string
	if *format == "md" {
		output = export.GenerateMarkdownRunbook(kitData)
	} else {
		output, err = export.GenerateHTMLRunbook(kitData)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed generating HTML runbook: %v\n", err)
			os.Exit(1)
		}
	}

	if *outPath != "" {
		if err := os.WriteFile(*outPath, []byte(output), 0644); err != nil {
			fmt.Fprintf(os.Stderr, "Failed writing output file: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("✓ Emergency Recovery Kit written to %s\n", *outPath)
	} else {
		fmt.Println(output)
	}
}

// 8. Audit
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
	valid, count, lastHash, err := ledger.VerifyChain(context.Background())
	if err != nil || !valid {
		fmt.Printf("✗ Audit Chain Broken: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("✓ Cryptographic Audit Chain Valid (%d events verified)\n", count)
	fmt.Printf("  Latest Hash: %s\n", lastHash)
}

// 9. Pair
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
		fmt.Println("\nSave this API Token in your service configuration to push automated backups.")

	case "push":
		fs := flag.NewFlagSet("pair push", flag.ExitOnError)
		serverURL := fs.String("server", "http://localhost:8080", "KyRecovery server URL")
		token := fs.String("token", "", "API Bearer Token from pairing")
		serviceName := fs.String("service", "generic", "Service name (e.g. kynotes, kybookmarks, kypost)")
		appName := fs.String("app", "KySecurity Client", "Application name")
		appVer := fs.String("version", "1.0.0", "Application version")
		dirPath := fs.String("dir", "", "Directory path containing database and configuration files")
		threshold := fs.Int("threshold", 2, "Quorum threshold")
		total := fs.Int("shares", 3, "Total Shamir shares")
		fs.Parse(args[1:])

		if *token == "" || *dirPath == "" {
			fmt.Fprintln(os.Stderr, "Error: --token and --dir are required")
			os.Exit(1)
		}

		c := client.NewClient(*serverURL, *token)
		pushResp, err := c.PushDirectory(context.Background(), *serviceName, *appName, *appVer, *dirPath, *threshold, *total)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Backup push failed: %v\n", err)
			os.Exit(1)
		}

		fmt.Println("=== BACKUP PUSH INGESTED & VERIFIED ===")
		fmt.Printf("Capsule ID:   %s\n", pushResp.CapsuleID)
		fmt.Printf("Service:      %s\n", pushResp.ServiceName)
		fmt.Printf("Size:         %.2f KB\n", float64(pushResp.SizeBytes)/1024)
		fmt.Printf("Payload Hash: %s\n", pushResp.PayloadHash)
		fmt.Println("\n--- Custodian Secret Shares (STORE SECURELY) ---")
		for _, s := range pushResp.Shares {
			fmt.Printf("  %v-%v\n", s["index"], s["value_hex"])
		}

	default:
		fmt.Fprintf(os.Stderr, "Unknown pairing sub-action %q (valid: generate, list, claim, push)\n", action)
		os.Exit(1)
	}
}

// 10. TUI Air-Gapped Console
func cmdTUI(args []string) {
	fs := flag.NewFlagSet("tui", flag.ExitOnError)
	dataDir := fs.String("data-dir", "./data", "KyRecovery data directory")
	dbPath := fs.String("db", "", "SQLite database path (defaults to <data-dir>/recovery.db)")
	_ = fs.Parse(args)

	if *dbPath == "" {
		*dbPath = filepath.Join(*dataDir, "recovery.db")
	}

	database, err := db.Open(*dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed opening database: %v\n", err)
		os.Exit(1)
	}
	defer database.Close()

	ledger := audit.NewLedger(database)
	console := tui.NewConsole(*dataDir, database, ledger)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	console.Run(ctx)
}
