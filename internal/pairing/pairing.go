package pairing

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
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
	apiToken := fmt.Sprintf("kyrec_%s", hex.EncodeToString(tokenBytes))

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

// SelfDeclaredBackupPayload represents the wire format of an automated self-declaring backup.
type SelfDeclaredBackupPayload struct {
	ServiceName  string                     `json:"service_name"`
	AppName      string                     `json:"app_name"`
	AppVersion   string                     `json:"app_version"`
	Threshold    int                        `json:"threshold"`
	TotalShares  int                        `json:"total_shares"`
	Dependencies []capsule.Dependency       `json:"dependencies"`
	VerifyRecipe adapter.GenericVerifyRules `json:"verify_recipe"`
	Files        map[string]string          `json:"files"` // relative path -> base64 encoded file data
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
		data, err := base64.StdEncoding.DecodeString(b64Content)
		if err != nil {
			return nil, nil, adapter.GenericRecipe{}, fmt.Errorf("invalid base64 content for file %s: %w", relPath, err)
		}
		rawFiles[relPath] = data
	}

	recipe := adapter.GenericRecipe{
		ServiceName:  payload.ServiceName,
		Dependencies: payload.Dependencies,
		VerifyChecks: payload.VerifyRecipe,
	}

	return rawFiles, payload.Dependencies, recipe, nil
}
