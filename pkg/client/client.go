package client

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// Client provides an easy Go integration SDK for pushing self-declared backups to KyRecovery Server.
type Client struct {
	ServerURL  string
	APIToken   string
	HTTPClient *http.Client
}

// NewClient creates a new KyRecovery client instance.
func NewClient(serverURL, apiToken string) *Client {
	return &Client{
		ServerURL:  serverURL,
		APIToken:   apiToken,
		HTTPClient: &http.Client{Timeout: 60 * time.Second},
	}
}

// ClaimResponse returned upon claiming an ephemeral pairing code.
type ClaimResponse struct {
	ID          string     `json:"id"`
	ServiceName string     `json:"service_name"`
	AppName     string     `json:"app_name"`
	APIToken    string     `json:"api_token"`
	Status      string     `json:"status"`
	PairedAt    *time.Time `json:"paired_at,omitempty"`
}

// ClaimPairing exchanges a 6-digit PIN code for a permanent client Bearer token.
func ClaimPairing(ctx context.Context, serverURL, pairingCode, appName string) (*Client, *ClaimResponse, error) {
	payload := map[string]string{
		"pairing_code": pairingCode,
		"app_name":     appName,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, fmt.Sprintf("%s/api/pairing/claim", serverURL), bytes.NewReader(body))
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("pairing request failed: %w", err)
	}
	defer resp.Body.Close()

	respBytes, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("pairing claim rejected (HTTP %d): %s", resp.StatusCode, string(respBytes))
	}

	var claimResp ClaimResponse
	if err := json.Unmarshal(respBytes, &claimResp); err != nil {
		return nil, nil, fmt.Errorf("failed decoding claim response: %w", err)
	}

	return NewClient(serverURL, claimResp.APIToken), &claimResp, nil
}

// BackupPushPayload represents the self-declared payload pushed to KyRecovery.
type BackupPushPayload struct {
	ServiceName  string                   `json:"service_name"`
	AppName      string                   `json:"app_name"`
	AppVersion   string                   `json:"app_version"`
	Threshold    int                      `json:"threshold"`
	TotalShares  int                      `json:"total_shares"`
	Passphrase   string                   `json:"passphrase,omitempty"`
	Dependencies []map[string]interface{} `json:"dependencies,omitempty"`
	VerifyRecipe map[string]interface{}   `json:"verify_recipe,omitempty"`
	Files        map[string]string        `json:"files"` // relative_path -> base64_content
}

// PushResponse returned by KyRecovery upon successful ingest and drill.
type PushResponse struct {
	Status       string                   `json:"status"`
	CapsuleID    string                   `json:"capsule_id"`
	ServiceName  string                   `json:"service_name"`
	SizeBytes    int64                    `json:"size_bytes"`
	PayloadHash  string                   `json:"payload_hash"`
	Shares       []map[string]interface{} `json:"shares,omitempty"`
	DrillSummary map[string]interface{}   `json:"drill_summary,omitempty"`
}

// PushBackup uploads a self-declared backup payload to KyRecovery.
func (c *Client) PushBackup(ctx context.Context, payload BackupPushPayload) (*PushResponse, error) {
	if payload.Threshold <= 0 {
		payload.Threshold = 2
	}
	if payload.TotalShares <= 0 {
		payload.TotalShares = 3
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, fmt.Sprintf("%s/api/backup/push", c.ServerURL), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.APIToken))
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("backup push request failed: %w", err)
	}
	defer resp.Body.Close()

	respBytes, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("backup push rejected (HTTP %d): %s", resp.StatusCode, string(respBytes))
	}

	var pushResp PushResponse
	if err := json.Unmarshal(respBytes, &pushResp); err != nil {
		return nil, fmt.Errorf("failed decoding push response: %w", err)
	}

	return &pushResp, nil
}

// PushDirectory gathers files from a local service directory and pushes them as a self-declared backup.
func (c *Client) PushDirectory(ctx context.Context, serviceName, appName, appVersion, dirPath string, threshold, totalShares int) (*PushResponse, error) {
	files := make(map[string]string)

	err := filepath.WalkDir(dirPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		relPath, err := filepath.Rel(dirPath, path)
		if err != nil {
			return nil
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		files[relPath] = base64.StdEncoding.EncodeToString(content)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed reading directory %s: %w", dirPath, err)
	}

	payload := BackupPushPayload{
		ServiceName: serviceName,
		AppName:     appName,
		AppVersion:  appVersion,
		Threshold:   threshold,
		TotalShares: totalShares,
		Files:       files,
		VerifyRecipe: map[string]interface{}{
			"check_sqlite_databases": true,
			"validate_certificates":  true,
			"validate_json_files":    true,
		},
	}

	return c.PushBackup(ctx, payload)
}
