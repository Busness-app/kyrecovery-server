package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Client is the Go SDK for talking to a KyRecovery server.
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
	// RecoveryPublicKey is the suite recovery public key this store pins, standard base64.
	// Everything the product later deposits must be sealed to it.
	RecoveryPublicKey string `json:"recovery_public_key"`
	Threshold         int    `json:"threshold"`
	TotalShares       int    `json:"total_shares"`
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

	resp, err := (&http.Client{Timeout: 60 * time.Second}).Do(req)
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

	if claimResp.RecoveryPublicKey == "" {
		return nil, nil, fmt.Errorf("server returned no recovery public key; the ceremony has not run")
	}

	return NewClient(serverURL, claimResp.APIToken), &claimResp, nil
}

// DepositResponse is what the store returns for a stored container.
type DepositResponse struct {
	CapsuleID   string    `json:"capsule_id"`
	Digest      string    `json:"digest"`
	SizeBytes   int64     `json:"size_bytes"`
	DepositedAt time.Time `json:"deposited_at"`
}

// Deposit stores a sealed container. The bytes are opaque to the server; it can only check
// that they are sealed to the key it handed out at pairing.
func (c *Client) Deposit(ctx context.Context, container []byte) (*DepositResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.ServerURL+"/api/backup/deposit", bytes.NewReader(container))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.APIToken)
	req.Header.Set("Content-Type", "application/octet-stream")
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("deposit: %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	var out DepositResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
