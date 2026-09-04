package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
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

	return NewClient(serverURL, claimResp.APIToken), &claimResp, nil
}
