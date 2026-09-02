package capsule

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Busness-app/kyrecovery-server/internal/crypto"
)

// Dependency describes a prerequisite environment, certificate, or network service.
type Dependency struct {
	Name        string `json:"name"`
	Type        string `json:"type"` // "env", "port", "cert", "database"
	Required    bool   `json:"required"`
	Description string `json:"description"`
}

// FileEntry records metadata about an included file within the capsule.
type FileEntry struct {
	Path      string `json:"path"`
	SizeBytes int64  `json:"size_bytes"`
	SHA256    string `json:"sha256"`
	Mode      int64  `json:"mode"`
}

// Manifest defines the public and integrity metadata of a recovery capsule.
type Manifest struct {
	Version      int          `json:"version"`
	CapsuleID    string       `json:"capsule_id"`
	ServiceName  string       `json:"service_name"`
	CreatedAt    time.Time    `json:"created_at"`
	Threshold    int          `json:"threshold"`
	TotalShares  int          `json:"total_shares"`
	Dependencies []Dependency `json:"dependencies"`
	Files        []FileEntry  `json:"files"`
	PayloadHash  string       `json:"payload_hash"`
	AAD          string       `json:"aad"`
}

// PackOptions holds parameters for assembling an encrypted capsule.
type PackOptions struct {
	CapsuleID    string
	ServiceName  string
	Files        map[string][]byte // relative path -> file data
	Dependencies []Dependency
	Threshold    int
	TotalShares  int
	Passphrase   string // optional secondary password protection
}

// PackResult contains the packed capsule bytes, master key, shares, and manifest.
type PackResult struct {
	CapsuleBytes []byte
	MasterKey    []byte
	Shares       []crypto.Share
	Manifest     Manifest
}

// Pack creates an encrypted capsule archive (.kycap format) from raw file buffers.
func Pack(opts PackOptions) (*PackResult, error) {
	if opts.CapsuleID == "" {
		opts.CapsuleID = fmt.Sprintf("cap-%d", time.Now().UnixNano())
	}
	if opts.Threshold < 2 {
		opts.Threshold = 2
	}
	if opts.TotalShares < opts.Threshold {
		opts.TotalShares = opts.Threshold
	}

	// 1. Generate master key
	masterKey, err := crypto.GenerateMasterKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate master key: %w", err)
	}

	// 2. Split master key into Shamir shares
	shares, err := crypto.Split(masterKey, opts.Threshold, opts.TotalShares)
	if err != nil {
		return nil, fmt.Errorf("failed to split master key: %w", err)
	}

	// 3. Assemble tar.gz of payload files
	tarGzBuf := new(bytes.Buffer)
	gw := gzip.NewWriter(tarGzBuf)
	tw := tar.NewWriter(gw)

	var fileEntries []FileEntry
	for path, content := range opts.Files {
		h := sha256.Sum256(content)
		fileEntries = append(fileEntries, FileEntry{
			Path:      path,
			SizeBytes: int64(len(content)),
			SHA256:    hex.EncodeToString(h[:]),
			Mode:      0600,
		})

		hdr := &tar.Header{
			Name:    path,
			Mode:    0600,
			Size:    int64(len(content)),
			ModTime: time.Now().UTC(),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return nil, fmt.Errorf("failed to write tar header for %s: %w", path, err)
		}
		if _, err := tw.Write(content); err != nil {
			return nil, fmt.Errorf("failed to write file content for %s: %w", path, err)
		}
	}

	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := gw.Close(); err != nil {
		return nil, err
	}

	rawPayload := tarGzBuf.Bytes()
	payloadSum := sha256.Sum256(rawPayload)
	payloadHash := hex.EncodeToString(payloadSum[:])

	// 4. Create manifest
	manifest := Manifest{
		Version:      1,
		CapsuleID:    opts.CapsuleID,
		ServiceName:  opts.ServiceName,
		CreatedAt:    time.Now().UTC(),
		Threshold:    opts.Threshold,
		TotalShares:  opts.TotalShares,
		Dependencies: opts.Dependencies,
		Files:        fileEntries,
		PayloadHash:  payloadHash,
		AAD:          fmt.Sprintf("%s:%s", opts.CapsuleID, opts.ServiceName),
	}

	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal manifest: %w", err)
	}

	// 5. Encrypt payload with master key
	encPayload, nonce, err := crypto.EncryptAESGCM(rawPayload, masterKey, []byte(manifest.AAD))
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt payload: %w", err)
	}

	// 6. Bundle into outer .kycap archive (tar stream)
	capBuf := new(bytes.Buffer)
	outerTw := tar.NewWriter(capBuf)

	entries := []struct {
		name string
		data []byte
	}{
		{"manifest.json", manifestBytes},
		{"nonce.bin", nonce},
		{"payload.enc", encPayload},
	}

	for _, entry := range entries {
		hdr := &tar.Header{
			Name:    entry.name,
			Mode:    0644,
			Size:    int64(len(entry.data)),
			ModTime: time.Now().UTC(),
		}
		if err := outerTw.WriteHeader(hdr); err != nil {
			return nil, err
		}
		if _, err := outerTw.Write(entry.data); err != nil {
			return nil, err
		}
	}

	if err := outerTw.Close(); err != nil {
		return nil, err
	}

	return &PackResult{
		CapsuleBytes: capBuf.Bytes(),
		MasterKey:    masterKey,
		Shares:       shares,
		Manifest:     manifest,
	}, nil
}

// Unpack extracts and decrypts an encrypted .kycap archive using the recovered master key.
func Unpack(capsuleBytes []byte, masterKey []byte) (*Manifest, map[string][]byte, error) {
	tr := tar.NewReader(bytes.NewReader(capsuleBytes))

	var (
		manifestBytes []byte
		nonce         []byte
		payloadEnc    []byte
	)

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, nil, fmt.Errorf("error reading capsule archive: %w", err)
		}

		data, err := io.ReadAll(tr)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to read %s: %w", hdr.Name, err)
		}

		switch hdr.Name {
		case "manifest.json":
			manifestBytes = data
		case "nonce.bin":
			nonce = data
		case "payload.enc":
			payloadEnc = data
		}
	}

	if len(manifestBytes) == 0 {
		return nil, nil, errors.New("missing manifest.json in capsule")
	}
	if len(nonce) == 0 {
		return nil, nil, errors.New("missing nonce.bin in capsule")
	}
	if len(payloadEnc) == 0 {
		return nil, nil, errors.New("missing payload.enc in capsule")
	}

	var manifest Manifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		return nil, nil, fmt.Errorf("invalid manifest: %w", err)
	}

	// Decrypt payload
	decryptedPayload, err := crypto.DecryptAESGCM(payloadEnc, masterKey, nonce, []byte(manifest.AAD))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decrypt capsule payload: %w", err)
	}

	// Verify decrypted payload hash
	sum := sha256.Sum256(decryptedPayload)
	actualHash := hex.EncodeToString(sum[:])
	if actualHash != manifest.PayloadHash {
		return nil, nil, fmt.Errorf("payload integrity check failed: hash mismatch (got %s, expected %s)", actualHash, manifest.PayloadHash)
	}

	// Extract files from decrypted tar.gz
	gr, err := gzip.NewReader(bytes.NewReader(decryptedPayload))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decompress payload gzip: %w", err)
	}
	defer gr.Close()

	innerTr := tar.NewReader(gr)
	files := make(map[string][]byte)

	for {
		hdr, err := innerTr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, nil, fmt.Errorf("failed to extract tar archive: %w", err)
		}
		content, err := io.ReadAll(innerTr)
		if err != nil {
			return nil, nil, fmt.Errorf("failed reading file %s: %w", hdr.Name, err)
		}
		files[hdr.Name] = content
	}

	// Verify individual file checksums
	for _, entry := range manifest.Files {
		data, exists := files[entry.Path]
		if !exists {
			return nil, nil, fmt.Errorf("missing expected file in payload: %s", entry.Path)
		}
		h := sha256.Sum256(data)
		hStr := hex.EncodeToString(h[:])
		if hStr != entry.SHA256 {
			return nil, nil, fmt.Errorf("checksum mismatch for file %s (got %s, expected %s)", entry.Path, hStr, entry.SHA256)
		}
	}

	return &manifest, files, nil
}

// ReadManifest extracts only the manifest without decrypting payload.
func ReadManifest(capsuleBytes []byte) (*Manifest, error) {
	tr := tar.NewReader(bytes.NewReader(capsuleBytes))
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed reading archive header: %w", err)
		}
		if hdr.Name == "manifest.json" {
			data, err := io.ReadAll(tr)
			if err != nil {
				return nil, err
			}
			var m Manifest
			if err := json.Unmarshal(data, &m); err != nil {
				return nil, err
			}
			return &m, nil
		}
	}
	return nil, errors.New("manifest.json not found in capsule")
}

// SafeJoin resolves relPath inside baseDir, refusing entries that escape it.
// Capsule contents come from paired clients, so every extraction path goes through here.
func SafeJoin(baseDir, relPath string) (string, error) {
	destPath := filepath.Join(baseDir, relPath)
	if destPath != baseDir && !strings.HasPrefix(destPath, baseDir+string(os.PathSeparator)) {
		return "", fmt.Errorf("unsafe capsule path escapes target directory: %s", relPath)
	}
	return destPath, nil
}

// ExtractToDirectory writes extracted files to a target directory.
func ExtractToDirectory(files map[string][]byte, targetDir string) error {
	if err := os.MkdirAll(targetDir, 0700); err != nil {
		return err
	}
	for relPath, content := range files {
		destPath, err := SafeJoin(targetDir, relPath)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(destPath), 0700); err != nil {
			return err
		}
		if err := os.WriteFile(destPath, content, 0600); err != nil {
			return err
		}
	}
	return nil
}
