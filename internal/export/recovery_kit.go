package export

import (
	"bytes"
	"fmt"
	"html/template"
	"strings"
	"time"

	"github.com/Busness-app/kyrecovery-server/internal/capsule"
	"github.com/Busness-app/kyrecovery-server/internal/db"
)

// KitData holds all details needed to render an Emergency Recovery Kit.
type KitData struct {
	CapsuleID    string
	ServiceName  string
	GeneratedAt  time.Time
	Threshold    int
	TotalShares  int
	PayloadHash  string
	Dependencies []capsule.Dependency
	Files        []capsule.FileEntry
	Custodians   []db.CustodianRecord
	LastDrill    *db.DrillRecord
}

// GenerateMarkdownRunbook produces an offline Markdown disaster recovery guide.
func GenerateMarkdownRunbook(data KitData) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("# EMERGENCY DISASTER RECOVERY KIT — %s\n\n", strings.ToUpper(data.ServiceName)))
	sb.WriteString(fmt.Sprintf("**Capsule ID:** `%s`  \n", data.CapsuleID))
	sb.WriteString(fmt.Sprintf("**Service Target:** `%s`  \n", data.ServiceName))
	sb.WriteString(fmt.Sprintf("**Generated At:** `%s`  \n", data.GeneratedAt.UTC().Format(time.RFC3339)))
	sb.WriteString(fmt.Sprintf("**Payload SHA-256:** `%s`  \n", data.PayloadHash))
	sb.WriteString(fmt.Sprintf("**Custodian Threshold Quorum:** `%d of %d` shares required to decrypt\n\n", data.Threshold, data.TotalShares))

	sb.WriteString("## 1. Emergency Restoration Workflow\n\n")
	sb.WriteString("To restore this capsule in a cold disaster recovery environment:\n\n")
	sb.WriteString("```bash\n")
	sb.WriteString("# Step 1: Collect threshold custodian shares\n")
	sb.WriteString(fmt.Sprintf("kyrecovery combine-shares --threshold %d \\\n", data.Threshold))
	sb.WriteString("  --share <SHARE_1> \\\n  --share <SHARE_2>\n\n")
	sb.WriteString("# Step 2: Decrypt and restore capsule contents\n")
	sb.WriteString(fmt.Sprintf("kyrecovery restore --capsule %s.kycap --key <MASTER_KEY> --target-dir /var/lib/%s\n", data.CapsuleID, data.ServiceName))
	sb.WriteString("```\n\n")

	sb.WriteString("## 2. Required Files & Integrity Manifest\n\n")
	sb.WriteString("| File Path | Size (Bytes) | SHA-256 Checksum |\n")
	sb.WriteString("| :--- | :--- | :--- |\n")
	for _, f := range data.Files {
		sb.WriteString(fmt.Sprintf("| `%s` | %d | `%s` |\n", f.Path, f.SizeBytes, f.SHA256))
	}
	sb.WriteString("\n")

	sb.WriteString("## 3. Required Environment & Network Dependencies\n\n")
	sb.WriteString("| Dependency | Type | Required | Description |\n")
	sb.WriteString("| :--- | :--- | :--- | :--- |\n")
	for _, d := range data.Dependencies {
		sb.WriteString(fmt.Sprintf("| `%s` | %s | %v | %s |\n", d.Name, d.Type, d.Required, d.Description))
	}
	sb.WriteString("\n")

	sb.WriteString("## 4. Designated Custodians\n\n")
	if len(data.Custodians) > 0 {
		sb.WriteString("| Name | Email | Key Fingerprint | Physical Sign-off |\n")
		sb.WriteString("| :--- | :--- | :--- | :--- |\n")
		for _, c := range data.Custodians {
			sb.WriteString(fmt.Sprintf("| %s | %s | `%s` | ____________________ |\n", c.Name, c.Email, c.Fingerprint))
		}
	} else {
		sb.WriteString("*(No custodians registered in directory at generation time)*\n")
	}
	sb.WriteString("\n")

	sb.WriteString("## 5. Verification & Drill History\n\n")
	if data.LastDrill != nil {
		sb.WriteString(fmt.Sprintf("- **Last Verified Drill ID:** `%s`\n", data.LastDrill.ID))
		sb.WriteString(fmt.Sprintf("- **Verification Status:** **%s**\n", strings.ToUpper(data.LastDrill.Status)))
		sb.WriteString(fmt.Sprintf("- **Recovery Time (RTO):** `%d ms`\n", data.LastDrill.DurationMs))
		sb.WriteString(fmt.Sprintf("- **Completed At:** `%s`\n", data.LastDrill.CompletedAt.UTC().Format(time.RFC3339)))
	} else {
		sb.WriteString("*(No automated drill recorded yet)*\n")
	}

	return sb.String()
}

var htmlTemplate = template.Must(template.New("recoveryKit").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Emergency Recovery Kit — {{.ServiceName}}</title>
<style>
  body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, monospace;
    background: #0d0f14;
    color: #e1e7ec;
    margin: 0;
    padding: 30px;
    line-height: 1.6;
  }
  .container {
    max-width: 900px;
    margin: 0 auto;
    background: #161922;
    padding: 40px;
    border-radius: 8px;
    border: 1px solid #222736;
  }
  h1, h2, h3 { color: #4deeea; }
  h1 { border-bottom: 2px solid #222736; padding-bottom: 15px; margin-top: 0; }
  .badge {
    display: inline-block;
    padding: 4px 10px;
    background: rgba(77, 238, 234, 0.15);
    color: #4deeea;
    border-radius: 4px;
    font-size: 13px;
    font-weight: 600;
  }
  .grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 15px;
    margin: 20px 0;
  }
  .card {
    background: #1e2230;
    padding: 15px;
    border-radius: 6px;
    border: 1px solid #2d3345;
  }
  .card label { font-size: 11px; text-transform: uppercase; color: #8a99ad; display: block; }
  .card span { font-size: 16px; font-weight: bold; color: #ffffff; }
  table {
    width: 100%;
    border-collapse: collapse;
    margin: 15px 0 25px 0;
  }
  th, td {
    padding: 10px 12px;
    text-align: left;
    border-bottom: 1px solid #222736;
    font-size: 14px;
  }
  th { background: #1b1f2b; color: #8a99ad; font-size: 12px; text-transform: uppercase; }
  code {
    background: #0d0f14;
    padding: 2px 6px;
    border-radius: 4px;
    color: #4deeea;
    font-family: "IBM Plex Mono", monospace;
    font-size: 13px;
  }
  pre {
    background: #0d0f14;
    padding: 15px;
    border-radius: 6px;
    overflow-x: auto;
    border: 1px solid #222736;
    color: #4deeea;
  }
  @media print {
    body { background: #fff; color: #000; padding: 0; }
    .container { background: #fff; border: none; padding: 0; }
    h1, h2, h3 { color: #000; }
    .card { background: #f5f5f5; border: 1px solid #ddd; }
    table, th, td { border-color: #ddd; color: #000; }
    th { background: #eee; }
    code, pre { background: #f5f5f5; color: #000; border-color: #ddd; }
  }
</style>
</head>
<body>
<div class="container">
  <h1>KySecurity Emergency Recovery Kit</h1>
  <p>Self-contained cold-restore runbook for <strong>{{.ServiceName}}</strong>.</p>

  <div class="grid">
    <div class="card">
      <label>Capsule ID</label>
      <span>{{.CapsuleID}}</span>
    </div>
    <div class="card">
      <label>Quorum Policy</label>
      <span>{{.Threshold}} of {{.TotalShares}} Custodian Shares Required</span>
    </div>
    <div class="card">
      <label>Payload SHA-256</label>
      <span style="font-size: 12px; word-break: break-all;">{{.PayloadHash}}</span>
    </div>
    <div class="card">
      <label>Kit Generated</label>
      <span>{{.GeneratedAt.Format "2006-01-02 15:04:05 UTC"}}</span>
    </div>
  </div>

  <h2>1. Emergency CLI Recovery Command</h2>
  <pre><code># Combine custodian threshold shares
kyrecovery combine-shares --threshold {{.Threshold}} --shares &lt;SHARE_1&gt;,&lt;SHARE_2&gt;

# Decrypt and restore capsule files into destination
kyrecovery restore --capsule {{.CapsuleID}}.kycap --key &lt;RECONSTRUCTED_KEY&gt; --target /var/lib/{{.ServiceName}}</code></pre>

  <h2>2. Required Files Manifest</h2>
  <table>
    <thead><tr><th>File Path</th><th>Size</th><th>SHA-256 Checksum</th></tr></thead>
    <tbody>
    {{range .Files}}
      <tr>
        <td><code>{{.Path}}</code></td>
        <td>{{.SizeBytes}} bytes</td>
        <td><code>{{.SHA256}}</code></td>
      </tr>
    {{end}}
    </tbody>
  </table>

  <h2>3. Required Environment & Dependencies</h2>
  <table>
    <thead><tr><th>Dependency</th><th>Type</th><th>Required</th><th>Description</th></tr></thead>
    <tbody>
    {{range .Dependencies}}
      <tr>
        <td><code>{{.Name}}</code></td>
        <td><span class="badge">{{.Type}}</span></td>
        <td>{{if .Required}}Yes{{else}}No{{end}}</td>
        <td>{{.Description}}</td>
      </tr>
    {{end}}
    </tbody>
  </table>

  <h2>4. Designated Custodian Sign-Off</h2>
  <table>
    <thead><tr><th>Custodian Name</th><th>Email</th><th>Fingerprint</th><th>Sign-off Signature</th></tr></thead>
    <tbody>
    {{range .Custodians}}
      <tr>
        <td><strong>{{.Name}}</strong></td>
        <td>{{.Email}}</td>
        <td><code>{{.Fingerprint}}</code></td>
        <td>_______________________________</td>
      </tr>
    {{else}}
      <tr><td colspan="4">No designated custodians recorded at generation time.</td></tr>
    {{end}}
    </tbody>
  </table>

  {{if .LastDrill}}
  <h2>5. Last Verified Restore Drill</h2>
  <div class="grid">
    <div class="card">
      <label>Drill Status</label>
      <span style="color: #2ecc71;">{{.LastDrill.Status}}</span>
    </div>
    <div class="card">
      <label>Recovery Time Objective (RTO)</label>
      <span>{{.LastDrill.DurationMs}} ms</span>
    </div>
  </div>
  {{end}}
</div>
</body>
</html>`))

// GenerateHTMLRunbook produces a standalone, print-ready HTML disaster recovery kit.
func GenerateHTMLRunbook(data KitData) (string, error) {
	buf := new(bytes.Buffer)
	if err := htmlTemplate.Execute(buf, data); err != nil {
		return "", err
	}
	return buf.String(), nil
}
