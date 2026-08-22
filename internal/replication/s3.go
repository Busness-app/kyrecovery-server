package replication

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// S3Client provides pure-Go AWS SigV4 signed operations for S3 and Cloudflare R2.
type S3Client struct {
	Endpoint  string
	Bucket    string
	Region    string
	AccessKey string
	SecretKey string
	client    *http.Client
}

// NewS3Client creates a new S3 client.
func NewS3Client(endpoint, bucket, region, accessKey, secretKey string) *S3Client {
	if region == "" {
		region = "us-east-1"
	}
	if endpoint == "" {
		endpoint = fmt.Sprintf("https://%s.s3.%s.amazonaws.com", bucket, region)
	}
	return &S3Client{
		Endpoint:  strings.TrimRight(endpoint, "/"),
		Bucket:    bucket,
		Region:    region,
		AccessKey: accessKey,
		SecretKey: secretKey,
		client:    &http.Client{Timeout: 60 * time.Second},
	}
}

// PutObject uploads a stream/file to the target bucket with SigV4 signing.
func (c *S3Client) PutObject(ctx context.Context, key string, data io.Reader, size int64, contentType string) error {
	if contentType == "" {
		contentType = "application/octet-stream"
	}

	reqURL := c.buildURL(key)

	// SigV4 signs a hash of the body, so the body has to be read twice. A capsule
	// is a file, so hash one pass and rewind rather than holding the whole archive
	// in memory; anything not seekable falls back to buffering.
	var (
		body           io.Reader
		payloadHashHex string
	)
	if seeker, ok := data.(io.ReadSeeker); ok {
		h := sha256.New()
		n, err := io.Copy(h, seeker)
		if err != nil {
			return fmt.Errorf("failed hashing payload for upload: %w", err)
		}
		if _, err := seeker.Seek(0, io.SeekStart); err != nil {
			return fmt.Errorf("failed rewinding payload for upload: %w", err)
		}
		payloadHashHex = hex.EncodeToString(h.Sum(nil))
		size, body = n, seeker
	} else {
		bodyBytes, err := io.ReadAll(data)
		if err != nil {
			return fmt.Errorf("failed reading payload for upload: %w", err)
		}
		sum := sha256.Sum256(bodyBytes)
		payloadHashHex = hex.EncodeToString(sum[:])
		size, body = int64(len(bodyBytes)), bytes.NewReader(bodyBytes)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, reqURL, body)
	if err != nil {
		return err
	}
	req.ContentLength = size

	now := time.Now().UTC()
	dateStamp := now.Format("20060102")
	amzDate := now.Format("20060102T150405Z")

	parsedURL, _ := url.Parse(reqURL)
	host := parsedURL.Host

	req.Header.Set("Host", host)
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Content-Length", fmt.Sprintf("%d", size))
	req.Header.Set("x-amz-date", amzDate)
	req.Header.Set("x-amz-content-sha256", payloadHashHex)

	// Build Canonical Request
	canonicalHeaders := fmt.Sprintf("host:%s\nx-amz-content-sha256:%s\nx-amz-date:%s\n", host, payloadHashHex, amzDate)
	signedHeaders := "host;x-amz-content-sha256;x-amz-date"
	canonicalURI := parsedURL.EscapedPath()
	if canonicalURI == "" {
		canonicalURI = "/"
	}

	canonicalRequest := fmt.Sprintf("PUT\n%s\n\n%s\n%s\n%s", canonicalURI, canonicalHeaders, signedHeaders, payloadHashHex)
	canonicalRequestHash := sha256.Sum256([]byte(canonicalRequest))

	// String to Sign
	credentialScope := fmt.Sprintf("%s/%s/s3/aws4_request", dateStamp, c.Region)
	stringToSign := fmt.Sprintf("AWS4-HMAC-SHA256\n%s\n%s\n%s", amzDate, credentialScope, hex.EncodeToString(canonicalRequestHash[:]))

	// Signing Key
	signingKey := getSignatureKey(c.SecretKey, dateStamp, c.Region, "s3")
	signature := hmacSHA256(signingKey, []byte(stringToSign))
	signatureHex := hex.EncodeToString(signature)

	// Authorization Header
	authHeader := fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		c.AccessKey, credentialScope, signedHeaders, signatureHex)
	req.Header.Set("Authorization", authHeader)

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("S3 PUT request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("S3 upload returned HTTP %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// TestConnection verifies bucket accessibility by executing a signed HEAD or PUT ping.
func (c *S3Client) TestConnection(ctx context.Context) error {
	pingData := []byte("kyrecovery-ping-" + time.Now().UTC().Format(time.RFC3339))
	return c.PutObject(ctx, ".kyrecovery-ping", bytes.NewReader(pingData), int64(len(pingData)), "text/plain")
}

func (c *S3Client) buildURL(key string) string {
	key = strings.TrimPrefix(key, "/")
	if strings.Contains(c.Endpoint, c.Bucket) {
		return fmt.Sprintf("%s/%s", c.Endpoint, key)
	}
	return fmt.Sprintf("%s/%s/%s", c.Endpoint, c.Bucket, key)
}

func hmacSHA256(key []byte, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

func getSignatureKey(secret, dateStamp, regionName, serviceName string) []byte {
	kDate := hmacSHA256([]byte("AWS4"+secret), []byte(dateStamp))
	kRegion := hmacSHA256(kDate, []byte(regionName))
	kService := hmacSHA256(kRegion, []byte(serviceName))
	kSigning := hmacSHA256(kService, []byte("aws4_request"))
	return kSigning
}
