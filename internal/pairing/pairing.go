package pairing

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"kyrecovery-server/internal/adapter"
	"kyrecovery-server/internal/capsule"
	"kyrecovery-server/internal/db"
)

// GeneratePairingCode creates a new ephemeral pairing code for connecting a product.
func GeneratePairingCode(ctx context.Context, database *db.DB, ttl time.Duration, serviceName, appName string) (*db.PairedAppRecord, error) {
	if ttl <= 0 {
		ttl = 15 * time.Minute // 15-minute default pairing window
	}
	if serviceName == "" {
		serviceName = "auto-declare"
	}
	if appName == "" {
		appName = "Pending Service"
	}

	// Generate 6-digit pairing code (e.g. 748291) or alphanumeric PAIR-XXXX
	n, err := rand.Int(rand.Reader, big.NewInt(900000))
	if err != nil {
		return nil, fmt.Errorf("failed generating random pairing code: %w", err)
	}
	pairingCode := fmt.Sprintf("%06d", n.Int64()+100000)

	// Generate random 256-bit API token
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return nil, fmt.Errorf("failed generating api token: %w", err)
	}
	apiToken := fmt.Sprintf("kyrec_live_%s", hex.EncodeToString(tokenBytes))

	now := time.Now().UTC()
	record := db.PairedAppRecord{
		ID:          fmt.Sprintf("pair-%d", now.UnixNano()),
		ServiceName: serviceName,
		AppName:     appName,
		APIToken:    apiToken,
		PairingCode: pairingCode,
		Status:      "pending",
		ExpiresAt:   now.Add(ttl),
		CreatedAt:   now,
	}

	if err := database.InsertPairedApp(ctx, record); err != nil {
		return nil, fmt.Errorf("failed saving pairing record: %w", err)
	}

	return &record, nil
}

// BackupFiles accepts either the compact object form {"path": "<base64>"} or the
// published array form [{"path": ..., "data_base64": ..., "mode": ...}].
// ponytail: per-file mode is ignored — capsules restore 0600 inside a 0700 sandbox.
// Plumb it through capsule.Pack only if a service ever needs the executable bit back.
type BackupFiles map[string]string

func (f *BackupFiles) UnmarshalJSON(data []byte) error {
	data = bytes.TrimSpace(data)
	if len(data) == 0 || string(data) == "null" {
		return nil
	}
	if data[0] != '[' {
		var compact map[string]string
		if err := json.Unmarshal(data, &compact); err != nil {
			return err
		}
		*f = compact
		return nil
	}

	var entries []struct {
		Path       string `json:"path"`
		DataBase64 string `json:"data_base64"`
	}
	if err := json.Unmarshal(data, &entries); err != nil {
		return err
	}
	files := make(BackupFiles, len(entries))
	for _, entry := range entries {
		if entry.Path == "" {
			return errors.New("backup file entry is missing path")
		}
		files[entry.Path] = entry.DataBase64
	}
	*f = files
	return nil
}

// BackupDependencies accepts either an explicit capsule.Dependency array or the
// published declaration object {"ports": [8080], "env": ["KY_ISSUER"]}.
type BackupDependencies []capsule.Dependency

func (d *BackupDependencies) UnmarshalJSON(data []byte) error {
	data = bytes.TrimSpace(data)
	if len(data) == 0 || string(data) == "null" {
		return nil
	}
	if data[0] == '[' {
		var deps []capsule.Dependency
		if err := json.Unmarshal(data, &deps); err != nil {
			return err
		}
		*d = deps
		return nil
	}

	var declared struct {
		Ports []int    `json:"ports"`
		Env   []string `json:"env"`
	}
	if err := json.Unmarshal(data, &declared); err != nil {
		return err
	}
	deps := make(BackupDependencies, 0, len(declared.Ports)+len(declared.Env))
	for _, port := range declared.Ports {
		deps = append(deps, capsule.Dependency{
			Name: strconv.Itoa(port), Type: "port", Required: true, Description: "Declared service port",
		})
	}
	for _, env := range declared.Env {
		deps = append(deps, capsule.Dependency{
			Name: env, Type: "env", Required: true, Description: "Declared environment variable",
		})
	}
	*d = deps
	return nil
}

// SelfDeclaredBackupPayload represents the wire format of an automated self-declaring backup.
type SelfDeclaredBackupPayload struct {
	ServiceName  string                     `json:"service_name"`
	AppName      string                     `json:"app_name"`
	AppVersion   string                     `json:"app_version"`
	Threshold    int                        `json:"threshold"`
	TotalShares  int                        `json:"total_shares"`
	Dependencies BackupDependencies         `json:"dependencies"`
	VerifyRecipe adapter.GenericVerifyRules `json:"verify_recipe"`
	// VerificationRecipe is the published name for VerifyRecipe; either key is accepted.
	VerificationRecipe *adapter.GenericVerifyRules `json:"verification_recipe"`
	Files              BackupFiles                 `json:"files"` // relative path -> base64 encoded file data
}

// IngestSelfDeclaredBackup validates and decodes the files in a self-declared push.
func IngestSelfDeclaredBackup(payload SelfDeclaredBackupPayload) (map[string][]byte, []capsule.Dependency, adapter.GenericRecipe, error) {
	if payload.ServiceName == "" {
		return nil, nil, adapter.GenericRecipe{}, errors.New("service_name is required in self-declared backup")
	}
	if len(payload.Files) == 0 {
		return nil, nil, adapter.GenericRecipe{}, errors.New("no files provided in self-declared backup payload")
	}

	rawFiles := make(map[string][]byte)
	for relPath, b64Content := range payload.Files {
		if err := safeRelPath(relPath); err != nil {
			return nil, nil, adapter.GenericRecipe{}, err
		}
		data, err := base64.StdEncoding.DecodeString(b64Content)
		if err != nil {
			return nil, nil, adapter.GenericRecipe{}, fmt.Errorf("invalid base64 content for file %s: %w", relPath, err)
		}
		rawFiles[relPath] = data
	}

	if payload.VerificationRecipe != nil {
		payload.VerifyRecipe = *payload.VerificationRecipe
	}

	recipe := adapter.GenericRecipe{
		ServiceName:  payload.ServiceName,
		Dependencies: payload.Dependencies,
		VerifyChecks: payload.VerifyRecipe,
	}

	return rawFiles, payload.Dependencies, recipe, nil
}

// safeRelPath rejects capsule paths that would escape the restore directory.
func safeRelPath(relPath string) error {
	if relPath == "" {
		return errors.New("backup file path is empty")
	}
	if filepath.IsAbs(relPath) || strings.HasPrefix(filepath.ToSlash(relPath), "../") ||
		strings.Contains(filepath.ToSlash(relPath), "/../") || filepath.ToSlash(relPath) == ".." {
		return fmt.Errorf("unsafe backup file path: %s", relPath)
	}
	return nil
}
