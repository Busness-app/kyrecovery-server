package capsule

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"kyrecovery-server/internal/crypto"
)

const (
	// StreamChunkSize is the size of each encrypted chunk in streaming mode (1 MB)
	StreamChunkSize = 1024 * 1024
)

// PackDirectoryStream creates an encrypted .kycap archive directly from a disk directory to a target file.
// It operates in constant O(1) memory, allowing multi-gigabyte databases to be archived safely.
func PackDirectoryStream(sourceDir, destCapsulePath string, opts PackOptions) (*PackResult, error) {
	if opts.CapsuleID == "" {
		opts.CapsuleID = fmt.Sprintf("cap-%d", time.Now().UnixNano())
	}
	if opts.Threshold < 2 {
		opts.Threshold = 2
	}
	if opts.TotalShares < opts.Threshold {
		opts.TotalShares = opts.Threshold + 1
	}

	// 1. Generate master key & Shamir shares
	masterKey, err := crypto.GenerateMasterKey()
	if err != nil {
		return nil, fmt.Errorf("failed generating master key: %w", err)
	}

	shares, err := crypto.Split(masterKey, opts.Threshold, opts.TotalShares)
	if err != nil {
		return nil, fmt.Errorf("failed splitting master key: %w", err)
	}

	// 2. Scan files to generate manifest
	var fileEntries []FileEntry
	err = filepath.Walk(sourceDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		relPath, err := filepath.Rel(sourceDir, path)
		if err != nil {
			return nil
		}

		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()

		h := sha256.New()
		n, err := io.Copy(h, f)
		if err != nil {
			return err
		}

		fileEntries = append(fileEntries, FileEntry{
			Path:      relPath,
			SizeBytes: n,
			SHA256:    hex.EncodeToString(h.Sum(nil)),
			Mode:      int64(info.Mode()),
		})
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed scanning source directory: %w", err)
	}

	// 3. Create temporary file for uncompressed/gzipped payload stream
	tmpPayload, err := os.CreateTemp("", "kyrecovery-payload-*.tmp")
	if err != nil {
		return nil, fmt.Errorf("failed creating temporary payload file: %w", err)
	}
	defer os.Remove(tmpPayload.Name())
	defer tmpPayload.Close()

	payloadHasher := sha256.New()
	multiWriter := io.MultiWriter(tmpPayload, payloadHasher)

	gw := gzip.NewWriter(multiWriter)
	tw := tar.NewWriter(gw)

	for _, fe := range fileEntries {
		srcFile, err := os.Open(filepath.Join(sourceDir, fe.Path))
		if err != nil {
			return nil, fmt.Errorf("failed opening file %s: %w", fe.Path, err)
		}

		hdr := &tar.Header{
			Name:    fe.Path,
			Mode:    fe.Mode,
			Size:    fe.SizeBytes,
			ModTime: time.Now().UTC(),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			srcFile.Close()
			return nil, err
		}
		if _, err := io.Copy(tw, srcFile); err != nil {
			srcFile.Close()
			return nil, err
		}
		srcFile.Close()
	}

	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := gw.Close(); err != nil {
		return nil, err
	}

	payloadHashHex := hex.EncodeToString(payloadHasher.Sum(nil))

	manifest := Manifest{
		Version:      2, // Streaming schema
		CapsuleID:    opts.CapsuleID,
		ServiceName:  opts.ServiceName,
		CreatedAt:    time.Now().UTC(),
		Threshold:    opts.Threshold,
		TotalShares:  opts.TotalShares,
		Dependencies: opts.Dependencies,
		Files:        fileEntries,
		PayloadHash:  payloadHashHex,
		AAD:          fmt.Sprintf("%s:%s", opts.CapsuleID, opts.ServiceName),
	}

	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, err
	}

	// 4. Create destination .kycap tar container
	destFile, err := os.OpenFile(destCapsulePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return nil, fmt.Errorf("failed creating destination capsule: %w", err)
	}
	defer destFile.Close()

	outerTw := tar.NewWriter(destFile)

	// Write manifest.json header
	mHdr := &tar.Header{
		Name:    "manifest.json",
		Mode:    0644,
		Size:    int64(len(manifestBytes)),
		ModTime: time.Now().UTC(),
	}
	if err := outerTw.WriteHeader(mHdr); err != nil {
		return nil, err
	}
	if _, err := outerTw.Write(manifestBytes); err != nil {
		return nil, err
	}

	// Generate nonce
	nonce, err := crypto.GenerateRandomBytes(crypto.NonceLength)
	if err != nil {
		return nil, err
	}
	nHdr := &tar.Header{
		Name:    "nonce.bin",
		Mode:    0644,
		Size:    int64(len(nonce)),
		ModTime: time.Now().UTC(),
	}
	if err := outerTw.WriteHeader(nHdr); err != nil {
		return nil, err
	}
	if _, err := outerTw.Write(nonce); err != nil {
		return nil, err
	}

	// 5. Encrypt temporary payload stream in 1MB chunks directly into outer tar
	tmpPayload.Seek(0, io.SeekStart)
	payloadStat, _ := tmpPayload.Stat()

	// Calculate ciphertext size (each chunk adds 16 bytes auth tag + 4 byte chunk len)
	numChunks := (payloadStat.Size() + StreamChunkSize - 1) / StreamChunkSize
	if numChunks == 0 {
		numChunks = 1
	}
	encTotalSize := payloadStat.Size() + (numChunks * (16 + 4))

	pHdr := &tar.Header{
		Name:    "payload.stream.enc",
		Mode:    0644,
		Size:    encTotalSize,
		ModTime: time.Now().UTC(),
	}
	if err := outerTw.WriteHeader(pHdr); err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	buf := make([]byte, StreamChunkSize)
	chunkIndex := uint32(0)

	for {
		n, err := tmpPayload.Read(buf)
		if n > 0 {
			// Derive chunk nonce by XORing last 4 bytes with chunkIndex
			chunkNonce := make([]byte, len(nonce))
			copy(chunkNonce, nonce)
			binary.BigEndian.PutUint32(chunkNonce[len(chunkNonce)-4:], binary.BigEndian.Uint32(chunkNonce[len(chunkNonce)-4:])^chunkIndex)

			aad := fmt.Sprintf("%s:chunk:%d", manifest.AAD, chunkIndex)
			ciphertext := gcm.Seal(nil, chunkNonce, buf[:n], []byte(aad))

			// Write 4-byte chunk length header
			lenHeader := make([]byte, 4)
			binary.BigEndian.PutUint32(lenHeader, uint32(len(ciphertext)))
			if _, err := outerTw.Write(lenHeader); err != nil {
				return nil, err
			}
			if _, err := outerTw.Write(ciphertext); err != nil {
				return nil, err
			}
			chunkIndex++
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
	}

	if err := outerTw.Close(); err != nil {
		return nil, err
	}

	return &PackResult{
		CapsuleBytes: nil, // Streaming mode: written directly to disk
		MasterKey:    masterKey,
		Shares:       shares,
		Manifest:     manifest,
	}, nil
}

// UnpackToDirectoryStream unpacks a large streaming capsule directly to target directory in O(1) RAM.
func UnpackToDirectoryStream(capsulePath string, masterKey []byte, destDir string) (*Manifest, error) {
	capFile, err := os.Open(capsulePath)
	if err != nil {
		return nil, fmt.Errorf("failed opening capsule file: %w", err)
	}
	defer capFile.Close()

	tr := tar.NewReader(capFile)

	var (
		manifestBytes []byte
		nonce         []byte
		hasPayload    bool
		isStreamEnc   bool
	)

	var manifest Manifest

	// Pass 1: Extract manifest and nonce
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("error reading capsule headers: %w", err)
		}

		if hdr.Name == "manifest.json" {
			manifestBytes, _ = io.ReadAll(tr)
			_ = json.Unmarshal(manifestBytes, &manifest)
		} else if hdr.Name == "nonce.bin" {
			nonce, _ = io.ReadAll(tr)
		} else if hdr.Name == "payload.stream.enc" {
			hasPayload = true
			isStreamEnc = true
			break // Header ready for streaming decrypt
		} else if hdr.Name == "payload.enc" {
			hasPayload = true
			isStreamEnc = false
			break
		}
	}

	if len(manifestBytes) == 0 || len(nonce) == 0 || !hasPayload {
		// Fallback to in-memory unpack if not stream-encoded
		data, err := os.ReadFile(capsulePath)
		if err != nil {
			return nil, err
		}
		m, files, err := Unpack(data, masterKey)
		if err != nil {
			return nil, err
		}
		return m, ExtractToDirectory(files, destDir)
	}

	if !isStreamEnc {
		// Single chunk payload
		encData, err := io.ReadAll(tr)
		if err != nil {
			return nil, err
		}
		plain, err := crypto.DecryptAESGCM(encData, masterKey, nonce, []byte(manifest.AAD))
		if err != nil {
			return nil, err
		}
		gr, err := gzip.NewReader(bytes.NewReader(plain))
		if err != nil {
			return nil, err
		}
		defer gr.Close()
		return &manifest, extractTarReaderToDir(tar.NewReader(gr), destDir)
	}

	// Stream decrypt chunked payload to temporary decompressed tar pipe
	pr, pw := io.Pipe()

	go func() {
		defer pw.Close()
		block, err := aes.NewCipher(masterKey)
		if err != nil {
			pw.CloseWithError(err)
			return
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			pw.CloseWithError(err)
			return
		}

		lenBuf := make([]byte, 4)
		chunkIndex := uint32(0)

		for {
			_, err := io.ReadFull(tr, lenBuf)
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				break
			}
			if err != nil {
				pw.CloseWithError(err)
				return
			}

			chunkLen := binary.BigEndian.Uint32(lenBuf)
			cipherChunk := make([]byte, chunkLen)
			if _, err := io.ReadFull(tr, cipherChunk); err != nil {
				pw.CloseWithError(err)
				return
			}

			chunkNonce := make([]byte, len(nonce))
			copy(chunkNonce, nonce)
			binary.BigEndian.PutUint32(chunkNonce[len(chunkNonce)-4:], binary.BigEndian.Uint32(chunkNonce[len(chunkNonce)-4:])^chunkIndex)

			aad := fmt.Sprintf("%s:chunk:%d", manifest.AAD, chunkIndex)
			plainChunk, err := gcm.Open(nil, chunkNonce, cipherChunk, []byte(aad))
			if err != nil {
				pw.CloseWithError(errors.New("streaming decryption chunk authentication failed"))
				return
			}

			if _, err := pw.Write(plainChunk); err != nil {
				pw.CloseWithError(err)
				return
			}
			chunkIndex++
		}
	}()

	gr, err := gzip.NewReader(pr)
	if err != nil {
		return nil, fmt.Errorf("gzip stream error: %w", err)
	}
	defer gr.Close()

	if err := extractTarReaderToDir(tar.NewReader(gr), destDir); err != nil {
		return nil, err
	}

	return &manifest, nil
}

func extractTarReaderToDir(tr *tar.Reader, destDir string) error {
	if err := os.MkdirAll(destDir, 0700); err != nil {
		return err
	}
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		destPath := filepath.Join(destDir, hdr.Name)
		if hdr.Typeflag == tar.TypeDir {
			_ = os.MkdirAll(destPath, 0700)
			continue
		}

		if err := os.MkdirAll(filepath.Dir(destPath), 0700); err != nil {
			return err
		}

		outFile, err := os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
		if err != nil {
			return err
		}
		if _, err := io.Copy(outFile, tr); err != nil {
			outFile.Close()
			return err
		}
		outFile.Close()
	}
	return nil
}
