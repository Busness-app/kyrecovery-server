package export_test

import (
	"strings"
	"testing"
	"time"

	"kyrecovery-server/internal/capsule"
	"kyrecovery-server/internal/db"
	"kyrecovery-server/internal/export"
)

func TestGenerateRecoveryKit(t *testing.T) {
	data := export.KitData{
		CapsuleID:   "cap-sso-001",
		ServiceName: "kysignon",
		GeneratedAt: time.Now().UTC(),
		Threshold:   2,
		TotalShares: 4,
		PayloadHash: "sha256-dummy-hash-123456",
		Dependencies: []capsule.Dependency{
			{Name: "KY_ISSUER", Type: "env", Required: true, Description: "OIDC Issuer URL"},
		},
		Files: []capsule.FileEntry{
			{Path: "data/kysignon.db", SizeBytes: 16384, SHA256: "db-hash-abc", Mode: 0600},
		},
		Custodians: []db.CustodianRecord{
			{Name: "Alice Chief", Email: "alice@kysecurity.local", Fingerprint: "FP-1111"},
		},
		LastDrill: &db.DrillRecord{
			ID:          "drill-001",
			Status:      "passed",
			DurationMs:  85,
			CompletedAt: time.Now().UTC(),
		},
	}

	// 1. Test Markdown generation
	md := export.GenerateMarkdownRunbook(data)
	if !strings.Contains(md, "cap-sso-001") || !strings.Contains(md, "KY_ISSUER") || !strings.Contains(md, "Alice Chief") {
		t.Fatalf("Markdown runbook missing expected content: %s", md)
	}

	// 2. Test HTML generation
	html, err := export.GenerateHTMLRunbook(data)
	if err != nil {
		t.Fatalf("GenerateHTMLRunbook failed: %v", err)
	}
	if !strings.Contains(html, "<title>Emergency Recovery Kit — kysignon</title>") || !strings.Contains(html, "Alice Chief") {
		t.Fatalf("HTML runbook missing expected content: %s", html)
	}
}
