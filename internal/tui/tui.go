package tui

import (
	"bufio"
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"time"

	"kyrecovery-server/internal/adapter"
	"kyrecovery-server/internal/audit"
	"kyrecovery-server/internal/capsule"
	"kyrecovery-server/internal/crypto"
	"kyrecovery-server/internal/db"
	"kyrecovery-server/internal/drill"
)

// ANSI color codes
const (
	colorReset  = "\033[0m"
	colorBold   = "\033[1m"
	colorDim    = "\033[2m"
	colorCyan   = "\033[38;5;51m"
	colorGreen  = "\033[38;5;48m"
	colorAmber  = "\033[38;5;214m"
	colorRed    = "\033[38;5;196m"
	colorBgDark = "\033[48;5;234m"
)

// Console runs the interactive terminal disaster recovery console.
type Console struct {
	dataDir string
	db      *db.DB
	ledger  *audit.Ledger
	reader  *bufio.Reader
}

// NewConsole creates a new terminal console instance.
func NewConsole(dataDir string, database *db.DB, ledger *audit.Ledger) *Console {
	return &Console{
		dataDir: dataDir,
		db:      database,
		ledger:  ledger,
		reader:  bufio.NewReader(os.Stdin),
	}
}

// Run starts the interactive terminal loop.
func (c *Console) Run(ctx context.Context) {
	for {
		c.clearScreen()
		c.printBanner()
		c.printMenu()

		choice := c.prompt("Select option [1-6, Q to quit]: ")
		choice = strings.TrimSpace(strings.ToLower(choice))

		switch choice {
		case "1":
			c.handleRestoreWizard(ctx)
		case "2":
			c.handleDrillWizard(ctx)
		case "3":
			c.handleAuditVerification(ctx)
		case "4":
			c.handleKeySplitter()
		case "5":
			c.handleListCapsules(ctx)
		case "6":
			c.handlePairingList(ctx)
		case "q", "exit", "quit":
			fmt.Printf("\n%sExiting KyRecovery Air-Gapped Console. Stay resilient.%s\n\n", colorCyan, colorReset)
			return
		default:
			fmt.Printf("%sInvalid choice. Press Enter to continue...%s", colorRed, colorReset)
			c.reader.ReadString('\n')
		}
	}
}

func (c *Console) clearScreen() {
	fmt.Print("\033[H\033[2J")
}

func (c *Console) printBanner() {
	fmt.Printf("%s%s", colorCyan, colorBold)
	fmt.Println(`
 ██████╗██╗   ██╗██████╗ ███████╗ ██████╗ ██████╗ ██╗   ██╗███████╗██████╗ 
██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔════╝██╔═══██╗██║   ██║██╔════╝██╔══██╗
██║      ╚████╔╝ ██████╔╝█████╗  ██║     ██║   ██║██║   ██║█████╗  ██████╔╝
██║       ╚██╔╝  ██╔══██╗██╔══╝  ██║     ██║   ██║╚██╗ ██╔╝██╔══╝  ██╔══██╗
╚██████╗   ██║   ██████╔╝███████╗╚██████╗╚██████╔╝ ╚████╔╝ ███████╗██║  ██║
 ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝ ╚═════╝ ╚═════╝   ╚═══╝  ╚══════╝╚═╝  ╚═╝`)
	fmt.Printf("%sAIR-GAPPED DISASTER RECOVERY & VERIFICATION CONSOLE — PATINA v2.0%s\n", colorAmber, colorReset)
	fmt.Printf("%sData Directory: %s%s\n\n", colorDim, c.dataDir, colorReset)
}

func (c *Console) printMenu() {
	fmt.Printf("%s[1]%s 🛠️  Cold Disaster Restoration Wizard\n", colorBold, colorReset)
	fmt.Printf("%s[2]%s ⚡ Execute Ephemeral Verification Drill\n", colorBold, colorReset)
	fmt.Printf("%s[3]%s 🔗 Verify Tamper-Evident Audit Ledger\n", colorBold, colorReset)
	fmt.Printf("%s[4]%s 🔑 Shamir Quorum Key Splitter & Combiner\n", colorBold, colorReset)
	fmt.Printf("%s[5]%s 📦 Inspect Encrypted Recovery Capsules\n", colorBold, colorReset)
	fmt.Printf("%s[6]%s ⚡ Inspect Paired Products & Connectors\n", colorBold, colorReset)
	fmt.Printf("%s[Q]%s 🚪 Exit Console\n\n", colorBold, colorReset)
}

func (c *Console) prompt(label string) string {
	fmt.Printf("%s%s%s", colorCyan, label, colorReset)
	input, _ := c.reader.ReadString('\n')
	return strings.TrimSpace(input)
}

func (c *Console) waitEnter() {
	fmt.Printf("\n%sPress [Enter] to return to menu...%s", colorDim, colorReset)
	c.reader.ReadString('\n')
}

// 1. Cold Restoration Wizard
func (c *Console) handleRestoreWizard(ctx context.Context) {
	c.clearScreen()
	fmt.Printf("%s=== [1] COLD DISASTER RESTORATION WIZARD ===%s\n\n", colorBold, colorReset)

	capsulePath := c.prompt("Path to .kycap capsule file: ")
	if capsulePath == "" {
		return
	}
	if _, err := os.Stat(capsulePath); err != nil {
		fmt.Printf("%sError: File does not exist: %v%s\n", colorRed, err, colorReset)
		c.waitEnter()
		return
	}

	manifest, err := capsule.ReadManifestFromFile(capsulePath)
	if err != nil {
		fmt.Printf("%sFailed reading manifest: %v%s\n", colorRed, err, colorReset)
		c.waitEnter()
		return
	}

	fmt.Printf("\nCapsule ID:       %s%s%s\n", colorCyan, manifest.CapsuleID, colorReset)
	fmt.Printf("Service Name:     %s%s%s\n", colorCyan, manifest.ServiceName, colorReset)
	fmt.Printf("Quorum Threshold: %s%d of %d shares required%s\n\n", colorAmber, manifest.Threshold, manifest.TotalShares, colorReset)

	var key []byte
	method := c.prompt("Provide [1] Raw Hex Master Key or [2] Shamir Custodian Shares [1/2]: ")

	if method == "1" {
		hexKey := c.prompt("Enter 64-char Hex Master Key: ")
		key, err = hex.DecodeString(hexKey)
		if err != nil || len(key) != crypto.KeyLength {
			fmt.Printf("%sInvalid master key format%s\n", colorRed, colorReset)
			c.waitEnter()
			return
		}
	} else {
		fmt.Printf("Enter at least %d custodian shares (one per line, format: index-hex):\n", manifest.Threshold)
		var shares []crypto.Share
		for i := 0; i < manifest.Threshold; i++ {
			raw := c.prompt(fmt.Sprintf("Share #%d: ", i+1))
			sh, err := crypto.ParseShare(raw)
			if err != nil {
				fmt.Printf("%sInvalid share format: %v%s\n", colorRed, err, colorReset)
				c.waitEnter()
				return
			}
			shares = append(shares, sh)
		}
		key, err = crypto.Combine(shares, manifest.Threshold)
		if err != nil {
			fmt.Printf("%sKey reconstruction failed: %v%s\n", colorRed, err, colorReset)
			c.waitEnter()
			return
		}
	}

	targetDir := c.prompt("Target destination directory: ")
	if targetDir == "" {
		fmt.Printf("%sTarget directory required%s\n", colorRed, colorReset)
		c.waitEnter()
		return
	}

	fmt.Printf("\n%sDecrypting and restoring streaming payload...%s\n", colorCyan, colorReset)
	start := time.Now()
	_, err = capsule.UnpackToDirectoryStream(capsulePath, key, targetDir)
	if err != nil {
		fmt.Printf("%sRestoration failed: %v%s\n", colorRed, err, colorReset)
		c.waitEnter()
		return
	}

	duration := time.Since(start).Milliseconds()
	fmt.Printf("\n%s✓ RESTORATION SUCCESSFUL! (Duration: %d ms)%s\n", colorGreen, duration, colorReset)
	fmt.Printf("Restored payload to %s%s%s with constant O(1) RAM streaming.\n", colorBold, targetDir, colorReset)
	c.waitEnter()
}

// 2. Ephemeral Restore Drill
func (c *Console) handleDrillWizard(ctx context.Context) {
	c.clearScreen()
	fmt.Printf("%s=== [2] ISOLATED EPHEMERAL RESTORE DRILL ===%s\n\n", colorBold, colorReset)

	capsules, err := c.db.ListCapsules(ctx)
	if err != nil || len(capsules) == 0 {
		fmt.Println("No capsules found in database. Enter manual capsule path.")
	} else {
		fmt.Println("Available Capsules:")
		for i, cap := range capsules {
			fmt.Printf("  [%d] %s (%s, Quorum: %d/%d)\n", i+1, cap.ID, cap.ServiceName, cap.Threshold, cap.TotalShares)
		}
	}

	capsulePath := c.prompt("\nEnter path to .kycap file: ")
	if capsulePath == "" {
		return
	}

	manifest, err := capsule.ReadManifestFromFile(capsulePath)
	if err != nil {
		fmt.Printf("%sFailed reading manifest: %v%s\n", colorRed, err, colorReset)
		c.waitEnter()
		return
	}

	fmt.Printf("\nEnter %d custodian shares:\n", manifest.Threshold)
	var shares []crypto.Share
	for i := 0; i < manifest.Threshold; i++ {
		raw := c.prompt(fmt.Sprintf("Share #%d: ", i+1))
		sh, err := crypto.ParseShare(raw)
		if err != nil {
			fmt.Printf("%sInvalid share: %v%s\n", colorRed, err, colorReset)
			c.waitEnter()
			return
		}
		shares = append(shares, sh)
	}

	ssoAdapter := adapter.NewKySignOnAdapter()
	pwdAdapter := adapter.NewKyPasswordAdapter()
	bkmAdapter := adapter.NewKyBookmarksAdapter()
	notesAdapter := adapter.NewKyNotesAdapter()
	postAdapter := adapter.NewKyPostAdapter()
	genericAdapter := adapter.NewGenericAdapter()
	runner := drill.NewRunner(c.db, c.ledger, ssoAdapter, pwdAdapter, bkmAdapter, notesAdapter, postAdapter, genericAdapter)

	fmt.Printf("\n%sSpinning up ephemeral 0700 sandbox...%s\n", colorCyan, colorReset)
	summary, err := runner.Execute(ctx, drill.DrillParams{
		CapsulePath: capsulePath,
		Shares:      shares,
		Actor:       "tui-operator",
	})
	if err != nil {
		fmt.Printf("%sDrill failed: %v%s\n", colorRed, err, colorReset)
		c.waitEnter()
		return
	}

	fmt.Printf("\n=== DRILL EXECUTION SUMMARY ===\n")
	statusColor := colorGreen
	if !summary.Passed {
		statusColor = colorRed
	}
	fmt.Printf("Status:       %s%s%s\n", statusColor, strings.ToUpper(fmt.Sprintf("%v", summary.Passed)), colorReset)
	fmt.Printf("Duration RTO: %s%d ms%s\n", colorCyan, summary.DurationMs, colorReset)
	fmt.Println("\nVerification Checks:")
	for _, chk := range summary.Checks {
		passStr := fmt.Sprintf("%s[PASS]%s", colorGreen, colorReset)
		if !chk.Passed {
			passStr = fmt.Sprintf("%s[FAIL]%s", colorRed, colorReset)
		}
		fmt.Printf("  %s %-30s : %s\n", passStr, chk.Name, chk.Message)
	}

	c.waitEnter()
}

// 3. Audit Verification
func (c *Console) handleAuditVerification(ctx context.Context) {
	c.clearScreen()
	fmt.Printf("%s=== [3] CRYPTOGRAPHIC AUDIT LEDGER CHAIN VERIFIER ===%s\n\n", colorBold, colorReset)

	status, err := c.ledger.VerifyChain(ctx)
	if err != nil || !status.Valid {
		fmt.Printf("%s✗ AUDIT CHAIN COMPROMISED OR BROKEN: %v%s\n", colorRed, err, colorReset)
	} else {
		fmt.Printf("%s✓ AUDIT CHAIN FULLY VERIFIED%s\n", colorGreen, colorReset)
		fmt.Printf("  Verified Events: %s%d%s\n", colorBold, status.Count, colorReset)
		fmt.Printf("  Latest Hash:     %s%s%s\n", colorCyan, status.LastHash, colorReset)
	}

	fmt.Println("\nRecent Audit Stream:")
	events, _ := c.db.ListAuditEvents(ctx, 10)
	for _, e := range events {
		fmt.Printf("  #%-4d %s [%s] by %s (Target: %s) -> %s\n",
			e.SequenceNum, e.CreatedAt.Format("15:04:05"), e.Action, e.Actor, e.TargetID, e.EventHash[:8])
	}

	c.waitEnter()
}

// 4. Shamir Splitter
func (c *Console) handleKeySplitter() {
	c.clearScreen()
	fmt.Printf("%s=== [4] SHAMIR QUORUM KEY SPLITTER & COMBINER ===%s\n\n", colorBold, colorReset)

	subChoice := c.prompt("Choose [1] Split New Key or [2] Combine Shares [1/2]: ")
	if subChoice == "1" {
		threshold := 2
		total := 3
		key, _ := crypto.GenerateMasterKey()
		shares, _ := crypto.Split(key, threshold, total)

		fmt.Printf("\nGenerated Master Key (Hex): %s%s%s\n\n", colorCyan, hex.EncodeToString(key), colorReset)
		fmt.Printf("--- %d Custodian Shares Generated (Threshold: %d) ---\n", total, threshold)
		for _, sh := range shares {
			fmt.Printf("  %s\n", sh.String())
		}
	} else {
		threshold := 2
		fmt.Println("Enter 2 shares to combine:")
		sh1, _ := crypto.ParseShare(c.prompt("Share 1: "))
		sh2, _ := crypto.ParseShare(c.prompt("Share 2: "))
		key, err := crypto.Combine([]crypto.Share{sh1, sh2}, threshold)
		if err != nil {
			fmt.Printf("%sCombine failed: %v%s\n", colorRed, err, colorReset)
		} else {
			fmt.Printf("%s✓ Master Key: %s%s\n", colorGreen, hex.EncodeToString(key), colorReset)
		}
	}

	c.waitEnter()
}

// 5. List Capsules
func (c *Console) handleListCapsules(ctx context.Context) {
	c.clearScreen()
	fmt.Printf("%s=== [5] ENCRYPTED RECOVERY CAPSULES ===%s\n\n", colorBold, colorReset)

	capsules, err := c.db.ListCapsules(ctx)
	if err != nil || len(capsules) == 0 {
		fmt.Println("No capsules found in database.")
	} else {
		for _, cap := range capsules {
			fmt.Printf("• %s%s%s\n", colorBold, cap.ID, colorReset)
			fmt.Printf("  Service:   %s\n", cap.ServiceName)
			fmt.Printf("  File:      %s\n", cap.FilePath)
			fmt.Printf("  Size:      %.2f KB\n", float64(cap.SizeBytes)/1024)
			fmt.Printf("  Quorum:    %d of %d shares\n", cap.Threshold, cap.TotalShares)
			fmt.Printf("  Captured:  %s\n\n", cap.CreatedAt.Format(time.RFC3339))
		}
	}

	c.waitEnter()
}

// 6. Pairing List
func (c *Console) handlePairingList(ctx context.Context) {
	c.clearScreen()
	fmt.Printf("%s=== [6] PAIRED PRODUCTS & CONNECTORS ===%s\n\n", colorBold, colorReset)

	list, err := c.db.ListPairedApps(ctx)
	if err != nil || len(list) == 0 {
		fmt.Println("No paired applications found.")
	} else {
		for _, a := range list {
			fmt.Printf("• %s%s%s (%s)\n", colorBold, a.AppName, colorReset, a.ServiceName)
			fmt.Printf("  Status:    %s\n", a.Status)
			fmt.Printf("  Code/PIN:  %s\n", a.PairingCode)
			fmt.Printf("  Paired At: %v\n\n", a.PairedAt)
		}
	}

	c.waitEnter()
}
