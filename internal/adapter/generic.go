package adapter

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"kyrecovery-server/internal/capsule"
	_ "modernc.org/sqlite"
)

// GenericRecipe defines the declarative rules for capturing and verifying an arbitrary service.
type GenericRecipe struct {
	ServiceName  string               `json:"service_name"`
	IncludePaths []string             `json:"include_paths"` // Relative paths or globs to capture
	Dependencies []capsule.Dependency `json:"dependencies"`
	VerifyChecks GenericVerifyRules   `json:"verify_checks"`
}

// GenericVerifyRules defines automatic integrity checks during restore drills.
type GenericVerifyRules struct {
	CheckSQLiteDatabases bool     `json:"check_sqlite_databases"` // Run PRAGMA integrity_check on all .db files
	ValidateJSONFiles    bool     `json:"validate_json_files"`    // Validate JSON syntax on .json files
	ValidateCertificates bool     `json:"validate_certificates"`  // Validate TLS certs / keys on .pem, .crt, .key files
	RequiredFiles        []string `json:"required_files"`         // Explicit required file paths

	CheckSQLiteIntegrity bool     `json:"check_sqlite_integrity"` // Run PRAGMA integrity_check on SQLitePaths
	SQLitePaths          []string `json:"sqlite_paths"`           // Databases to integrity check by path
	TestSigningKeyPath   string   `json:"test_signing_key_path"`  // PEM private key to exercise with a sign/verify cycle
	SigningAlgorithm     string   `json:"signing_algorithm"`      // "rsa" or "ecdsa"; empty accepts either
	ExpectedEnv          []string `json:"expected_env"`           // Env var dependencies that must survive in the capsule
	ExpectedPorts        []int    `json:"expected_ports"`         // Port dependencies that must survive in the capsule
}

// GenericAdapter provides a pluggable, recipe-driven adapter for any application or service.
type GenericAdapter struct {
	defaultRecipe GenericRecipe
}

// NewGenericAdapter creates a generic connector with optional default recipe.
func NewGenericAdapter(defaultRecipe ...GenericRecipe) *GenericAdapter {
	recipe := GenericRecipe{
		ServiceName:  "generic",
		IncludePaths: []string{"data", "config", "keys"},
		VerifyChecks: GenericVerifyRules{
			CheckSQLiteDatabases: true,
			ValidateJSONFiles:    true,
			ValidateCertificates: true,
		},
	}
	if len(defaultRecipe) > 0 {
		recipe = defaultRecipe[0]
	}
	return &GenericAdapter{defaultRecipe: recipe}
}

func (g *GenericAdapter) Name() string {
	if g.defaultRecipe.ServiceName != "" {
		return g.defaultRecipe.ServiceName
	}
	return "generic"
}

// Capture walks the source directory and bundles files according to recipe rules.
func (g *GenericAdapter) Capture(ctx context.Context, sourceDir string) (map[string][]byte, []capsule.Dependency, error) {
	files := make(map[string][]byte)

	recipePath := filepath.Join(sourceDir, "kyrecovery-recipe.json")
	recipe := g.defaultRecipe
	if data, err := os.ReadFile(recipePath); err == nil {
		_ = json.Unmarshal(data, &recipe)
	}

	// If sourceDir doesn't exist on disk, generate sample generic files
	if _, err := os.Stat(sourceDir); os.IsNotExist(err) {
		return g.generateSamplePayload(recipe)
	}

	// Walk sourceDir and capture matching files
	err := filepath.WalkDir(sourceDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}

		relPath, err := filepath.Rel(sourceDir, path)
		if err != nil {
			return nil
		}

		// Check if file matches include paths or is default
		if g.shouldInclude(relPath, recipe.IncludePaths) {
			content, err := os.ReadFile(path)
			if err == nil {
				files[relPath] = content
			}
		}
		return nil
	})

	if err != nil {
		return nil, nil, fmt.Errorf("error reading source directory: %w", err)
	}

	if len(files) == 0 {
		return g.generateSamplePayload(recipe)
	}

	// Embed recipe into capsule for deterministic restore drill verification
	recipeBytes, _ := json.MarshalIndent(recipe, "", "  ")
	files["kyrecovery-recipe.json"] = recipeBytes

	return files, recipe.Dependencies, nil
}

func (g *GenericAdapter) shouldInclude(relPath string, includePaths []string) bool {
	if len(includePaths) == 0 {
		return true
	}
	for _, inc := range includePaths {
		if strings.HasPrefix(relPath, inc) || relPath == inc {
			return true
		}
		matched, _ := filepath.Match(inc, relPath)
		if matched {
			return true
		}
	}
	return false
}

// VerifyRestore inspects the restored generic payload using automated recipe verification rules.
func (g *GenericAdapter) VerifyRestore(ctx context.Context, extractedDir string, manifest *capsule.Manifest) (*DrillResult, error) {
	result := &DrillResult{
		Passed:  true,
		Details: make(map[string]interface{}),
	}

	recipe := g.defaultRecipe
	recipePath := filepath.Join(extractedDir, "kyrecovery-recipe.json")
	if data, err := os.ReadFile(recipePath); err == nil {
		_ = json.Unmarshal(data, &recipe)
	}

	// A recipe asking for integrity checks without naming paths falls back to the extension scan,
	// so check_sqlite_integrity is never a silent no-op.
	if recipe.VerifyChecks.CheckSQLiteIntegrity && len(recipe.VerifyChecks.SQLitePaths) == 0 {
		recipe.VerifyChecks.CheckSQLiteDatabases = true
	}

	var verifiedFilesCount int
	checkedDBs := make(map[string]bool)

	// 1. Required Files Check
	for _, reqFile := range recipe.VerifyChecks.RequiredFiles {
		p := filepath.Join(extractedDir, reqFile)
		info, err := os.Stat(p)
		switch {
		case err != nil:
			result.Passed = false
			result.Checks = append(result.Checks, CheckItem{
				Name:    fmt.Sprintf("required_file:%s", reqFile),
				Passed:  false,
				Message: fmt.Sprintf("Missing required file: %s", reqFile),
			})
		case info.Size() == 0:
			// An empty restored file is a failed restore, not a present one.
			result.Passed = false
			result.Checks = append(result.Checks, CheckItem{
				Name:    fmt.Sprintf("required_file:%s", reqFile),
				Passed:  false,
				Message: fmt.Sprintf("Required file restored empty: %s", reqFile),
			})
		default:
			result.Checks = append(result.Checks, CheckItem{
				Name:    fmt.Sprintf("required_file:%s", reqFile),
				Passed:  true,
				Message: fmt.Sprintf("File exists (%d bytes)", info.Size()),
			})
		}
	}

	// 1b. Databases named explicitly by the recipe
	if recipe.VerifyChecks.CheckSQLiteIntegrity {
		for _, relPath := range recipe.VerifyChecks.SQLitePaths {
			ok, msg := checkSQLiteIntegrity(ctx, filepath.Join(extractedDir, relPath))
			checkedDBs[relPath] = true
			if !ok {
				result.Passed = false
			}
			result.Checks = append(result.Checks, CheckItem{
				Name:    fmt.Sprintf("sqlite_check:%s", relPath),
				Passed:  ok,
				Message: msg,
			})
		}
	}

	// Walk extracted directory and run integrity checks
	err := filepath.WalkDir(extractedDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}

		relPath, _ := filepath.Rel(extractedDir, path)
		ext := strings.ToLower(filepath.Ext(path))
		verifiedFilesCount++

		// 2. Check SQLite Databases
		if recipe.VerifyChecks.CheckSQLiteDatabases && !checkedDBs[relPath] && (ext == ".db" || ext == ".sqlite" || ext == ".sqlite3") {
			ok, msg := checkSQLiteIntegrity(ctx, path)
			if !ok {
				result.Passed = false
			}
			result.Checks = append(result.Checks, CheckItem{
				Name:    fmt.Sprintf("sqlite_check:%s", relPath),
				Passed:  ok,
				Message: msg,
			})
		}

		// 3. Validate JSON Files
		if recipe.VerifyChecks.ValidateJSONFiles && ext == ".json" {
			data, err := os.ReadFile(path)
			if err == nil {
				var js interface{}
				if err := json.Unmarshal(data, &js); err != nil {
					result.Passed = false
					result.Checks = append(result.Checks, CheckItem{
						Name:    fmt.Sprintf("json_syntax:%s", relPath),
						Passed:  false,
						Message: fmt.Sprintf("Invalid JSON syntax: %v", err),
					})
				} else {
					result.Checks = append(result.Checks, CheckItem{
						Name:    fmt.Sprintf("json_syntax:%s", relPath),
						Passed:  true,
						Message: "Valid JSON syntax",
					})
				}
			}
		}

		// 4. Validate TLS Certificates / Private Keys
		if recipe.VerifyChecks.ValidateCertificates && (ext == ".pem" || ext == ".crt" || ext == ".cer" || ext == ".key") {
			data, err := os.ReadFile(path)
			if err == nil {
				block, _ := pem.Decode(data)
				if block != nil {
					if block.Type == "CERTIFICATE" || strings.Contains(block.Type, "CERTIFICATE") {
						cert, err := x509.ParseCertificate(block.Bytes)
						if err != nil {
							result.Passed = false
							result.Checks = append(result.Checks, CheckItem{
								Name:    fmt.Sprintf("cert_parse:%s", relPath),
								Passed:  false,
								Message: fmt.Sprintf("Failed parsing x509 cert: %v", err),
							})
						} else {
							expired := time.Now().After(cert.NotAfter)
							if expired {
								result.Passed = false
								result.Checks = append(result.Checks, CheckItem{
									Name:    fmt.Sprintf("cert_expiry:%s", relPath),
									Passed:  false,
									Message: fmt.Sprintf("Certificate expired on %s", cert.NotAfter.Format(time.RFC3339)),
								})
							} else {
								result.Checks = append(result.Checks, CheckItem{
									Name:    fmt.Sprintf("cert_validity:%s", relPath),
									Passed:  true,
									Message: fmt.Sprintf("Valid until %s (CN: %s)", cert.NotAfter.Format("2006-01-02"), cert.Subject.CommonName),
								})
							}
						}
					} else if block.Type == "RSA PRIVATE KEY" || block.Type == "PRIVATE KEY" {
						privKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
						if err != nil {
							// Try PKCS8
							_, err2 := x509.ParsePKCS8PrivateKey(block.Bytes)
							if err2 == nil {
								result.Checks = append(result.Checks, CheckItem{
									Name:    fmt.Sprintf("key_parse:%s", relPath),
									Passed:  true,
									Message: "Parsed valid PKCS#8 private key",
								})
							} else {
								result.Passed = false
								result.Checks = append(result.Checks, CheckItem{
									Name:    fmt.Sprintf("key_parse:%s", relPath),
									Passed:  false,
									Message: fmt.Sprintf("Failed parsing RSA/PKCS8 private key: %v", err),
								})
							}
						} else {
							result.Checks = append(result.Checks, CheckItem{
								Name:    fmt.Sprintf("rsa_key_validity:%s", relPath),
								Passed:  true,
								Message: fmt.Sprintf("Parsed valid RSA private key (%d bits)", privKey.N.BitLen()),
							})
						}
					} else if block.Type == "EC PRIVATE KEY" {
						ecKey, err := x509.ParseECPrivateKey(block.Bytes)
						if err != nil {
							result.Passed = false
							result.Checks = append(result.Checks, CheckItem{
								Name:    fmt.Sprintf("ec_key_parse:%s", relPath),
								Passed:  false,
								Message: fmt.Sprintf("Failed parsing EC private key: %v", err),
							})
						} else {
							result.Checks = append(result.Checks, CheckItem{
								Name:    fmt.Sprintf("ec_key_validity:%s", relPath),
								Passed:  true,
								Message: fmt.Sprintf("Parsed valid ECDSA private key (Curve: %s)", ecKey.Curve.Params().Name),
							})
						}
					}
				}
			}
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	result.Details["verified_files_count"] = verifiedFilesCount

	// 5. Prove the declared signing key still signs and verifies
	if keyPath := recipe.VerifyChecks.TestSigningKeyPath; keyPath != "" {
		ok, msg := testSigningKey(filepath.Join(extractedDir, keyPath), recipe.VerifyChecks.SigningAlgorithm)
		if !ok {
			result.Passed = false
		}
		result.Checks = append(result.Checks, CheckItem{
			Name:    fmt.Sprintf("signing_key:%s", keyPath),
			Passed:  ok,
			Message: msg,
		})
	}

	// 6. Declared environment variables and ports must survive in the capsule manifest
	if want := recipe.VerifyChecks.ExpectedEnv; len(want) > 0 {
		missing := missingDeclared(manifest.Dependencies, "env", want)
		result.MissingDependencies = append(result.MissingDependencies, missing...)
		result.Checks = append(result.Checks, CheckItem{
			Name:    "expected_env",
			Passed:  len(missing) == 0,
			Message: declarationMessage(len(want), "environment variables", missing),
		})
	}
	if want := recipe.VerifyChecks.ExpectedPorts; len(want) > 0 {
		names := make([]string, 0, len(want))
		for _, port := range want {
			names = append(names, strconv.Itoa(port))
		}
		missing := missingDeclared(manifest.Dependencies, "port", names)
		result.MissingDependencies = append(result.MissingDependencies, missing...)
		result.Checks = append(result.Checks, CheckItem{
			Name:    "expected_ports",
			Passed:  len(missing) == 0,
			Message: declarationMessage(len(want), "network ports", missing),
		})
	}

	// 7. Check dependencies
	for _, dep := range manifest.Dependencies {
		if dep.Required && dep.Name == "" {
			result.MissingDependencies = append(result.MissingDependencies, "unnamed_dependency")
		}
	}

	if len(result.MissingDependencies) > 0 {
		result.Passed = false
		result.Checks = append(result.Checks, CheckItem{Name: "dependencies", Passed: false, Message: fmt.Sprintf("Missing dependencies: %v", result.MissingDependencies)})
	} else {
		result.Checks = append(result.Checks, CheckItem{Name: "dependencies", Passed: true, Message: "All dependencies satisfied"})
	}

	if !result.Passed && result.ErrorMessage == "" {
		result.ErrorMessage = "One or more generic connector verification checks failed"
	}

	return result, nil
}

// checkSQLiteIntegrity runs PRAGMA integrity_check against a restored database file.
func checkSQLiteIntegrity(ctx context.Context, path string) (bool, string) {
	conn, err := sql.Open("sqlite", fmt.Sprintf("%s?_pragma=query_only(true)", path))
	if err != nil {
		return false, fmt.Sprintf("Failed opening SQLite DB: %v", err)
	}
	defer conn.Close()

	var integrity string
	if err := conn.QueryRowContext(ctx, "PRAGMA integrity_check").Scan(&integrity); err != nil || integrity != "ok" {
		return false, fmt.Sprintf("SQLite integrity check failed: %v (%s)", err, integrity)
	}
	return true, "SQLite integrity verified ok"
}

// testSigningKey proves a restored PEM private key can still sign and verify a digest.
func testSigningKey(path, algorithm string) (bool, string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return false, fmt.Sprintf("Missing signing key: %v", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return false, "Signing key is not valid PEM"
	}
	key, err := parsePrivateKey(block.Bytes)
	if err != nil {
		return false, fmt.Sprintf("Failed parsing private key: %v", err)
	}

	digest := sha256.Sum256([]byte("kyrecovery restore drill signing probe"))
	switch k := key.(type) {
	case *rsa.PrivateKey:
		if algorithm != "" && !strings.EqualFold(algorithm, "rsa") {
			return false, fmt.Sprintf("Recipe declared %q but the key is RSA", algorithm)
		}
		sig, err := rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, digest[:])
		if err != nil {
			return false, fmt.Sprintf("RSA signing failed: %v", err)
		}
		if err := rsa.VerifyPKCS1v15(&k.PublicKey, crypto.SHA256, digest[:], sig); err != nil {
			return false, fmt.Sprintf("RSA verification failed: %v", err)
		}
		return true, fmt.Sprintf("Parsed RSA private key (%d bits), signing & verification cycle passed", k.N.BitLen())
	case *ecdsa.PrivateKey:
		if algorithm != "" && !strings.EqualFold(algorithm, "ecdsa") {
			return false, fmt.Sprintf("Recipe declared %q but the key is ECDSA", algorithm)
		}
		sig, err := ecdsa.SignASN1(rand.Reader, k, digest[:])
		if err != nil {
			return false, fmt.Sprintf("ECDSA signing failed: %v", err)
		}
		if !ecdsa.VerifyASN1(&k.PublicKey, digest[:], sig) {
			return false, "ECDSA verification failed"
		}
		return true, fmt.Sprintf("Parsed ECDSA private key (Curve: %s), signing & verification cycle passed", k.Curve.Params().Name)
	default:
		return false, fmt.Sprintf("Unsupported signing key type %T", key)
	}
}

// parsePrivateKey accepts PKCS#1, PKCS#8, or SEC-1 encoded private keys.
func parsePrivateKey(der []byte) (any, error) {
	if k, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return k, nil
	}
	if k, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		return k, nil
	}
	return x509.ParseECPrivateKey(der)
}

// missingDeclared reports which wanted dependency names of depType are absent from deps.
func missingDeclared(deps []capsule.Dependency, depType string, want []string) []string {
	have := make(map[string]bool, len(deps))
	for _, dep := range deps {
		if strings.EqualFold(dep.Type, depType) {
			have[dep.Name] = true
		}
	}
	var missing []string
	for _, name := range want {
		if !have[name] {
			missing = append(missing, name)
		}
	}
	return missing
}

func declarationMessage(wanted int, kind string, missing []string) string {
	if len(missing) > 0 {
		return fmt.Sprintf("Missing declared %s: %v", kind, missing)
	}
	return fmt.Sprintf("All %d declared %s verified", wanted, kind)
}

func (g *GenericAdapter) generateSamplePayload(recipe GenericRecipe) (map[string][]byte, []capsule.Dependency, error) {
	files := make(map[string][]byte)

	switch recipe.ServiceName {
	case "kysignon":
		dbBytes, err := generateSampleKySignOnDB()
		if err != nil {
			return nil, nil, err
		}
		files["data/kysignon.db"] = dbBytes

		keyBytes, err := generateSampleRSAKeyPEM()
		if err != nil {
			return nil, nil, err
		}
		files["keys/token_signing_rsa.key"] = keyBytes
		files["config/kysignon.env"] = []byte("KY_ISSUER=https://auth.kysecurity.local\nKY_ADMIN_EMAIL=admin@kysecurity.local\nPORT_8080=8080\n")

	case "kypassword":
		dbBytes, err := generateSampleKyPasswordDB()
		if err != nil {
			return nil, nil, err
		}
		files["data/kypassword.db"] = dbBytes

		keyBytes, err := generateSampleECDSAKeyPEM()
		if err != nil {
			return nil, nil, err
		}
		files["keys/vault_ecdsa.key"] = keyBytes
		files["config/kypassword.env"] = []byte("KY_VAULT_SALT=kysec-vault-salt-xyz\nPORT_8081=8081\n")

	case "kybookmarks":
		dbBytes, err := generateSampleKyBookmarksDB()
		if err != nil {
			return nil, nil, err
		}
		files["data/bookmarks.db"] = dbBytes
		files["config/settings.json"] = []byte(`{"version": "1.2.0", "theme": "patina", "sync_enabled": true}`)

	case "kynotes":
		dbBytes, err := generateSampleKyNotesDB()
		if err != nil {
			return nil, nil, err
		}
		files["data/notes.db"] = dbBytes

		keyBytes, err := generateSampleRSAKeyPEM()
		if err != nil {
			return nil, nil, err
		}
		files["keys/jwt_notes_rsa.key"] = keyBytes
		files["config/kynotes.json"] = []byte(`{"appName": "KyNotes", "encryption": "AES-256-GCM", "max_attachments_mb": 50}`)

	case "kypost":
		dbBytes, err := generateSampleKyPostDB()
		if err != nil {
			return nil, nil, err
		}
		files["data/mail.db"] = dbBytes

		keyBytes, err := generateSampleRSAKeyPEM()
		if err != nil {
			return nil, nil, err
		}
		files["keys/dkim_rsa.key"] = keyBytes
		files["config/mail.json"] = []byte(`{"domain": "kysecurity.local", "smtp_port": 8084, "imap_port": 8085}`)

	default:
		// Sample SQLite DB
		dbBytes, err := generateSampleGenericDB()
		if err != nil {
			return nil, nil, err
		}
		files["data/app.db"] = dbBytes

		// Sample config
		files["config/app.json"] = []byte(`{"appName": "GenericService", "environment": "production", "version": "1.0.0"}`)
	}

	// Recipe
	recipeBytes, _ := json.MarshalIndent(recipe, "", "  ")
	files["kyrecovery-recipe.json"] = recipeBytes

	deps := recipe.Dependencies
	if len(deps) == 0 {
		deps = []capsule.Dependency{
			{Name: "APP_PORT", Type: "port", Required: true, Description: "Main application listener port"},
			{Name: "APP_SECRET", Type: "env", Required: true, Description: "Service secret key"},
		}
	}

	return files, deps, nil
}

func generateSampleGenericDB() ([]byte, error) {
	tmpFile, err := os.CreateTemp("", "generic-sample-*.db")
	if err != nil {
		return nil, err
	}
	tmpPath := tmpFile.Name()
	tmpFile.Close()
	defer os.Remove(tmpPath)

	dbConn, err := sql.Open("sqlite", tmpPath)
	if err != nil {
		return nil, err
	}

	schema := `
	CREATE TABLE records (
		id TEXT PRIMARY KEY,
		key TEXT NOT NULL,
		value TEXT NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	INSERT INTO records (id, key, value) VALUES ('1', 'system_mode', 'standard'), ('2', 'cluster_id', 'primary-01');
	`
	if _, err := dbConn.Exec(schema); err != nil {
		dbConn.Close()
		return nil, err
	}
	dbConn.Close()

	return os.ReadFile(tmpPath)
}
