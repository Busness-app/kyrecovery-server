package replication

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/Busness-app/ky-primitives/offsite"
	"github.com/Busness-app/kyrecovery-server/internal/db"
)

var replicaID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)

// location preserves the stored product contract; credentials never enter URLs.
// The two legacy flags cover target shapes the released module cannot represent.
type location struct {
	config       offsite.Config
	name         string
	absoluteSFTP bool
	virtualS3    bool
}

func targetLocation(t db.ReplicationTargetRecord, id string) (location, error) {
	if !replicaID.MatchString(id) {
		return location{}, errors.New("invalid capsule ID")
	}
	l := location{config: offsite.Config{AccessKey: t.AccessKey, Secret: t.SecretKey, HostKey: t.HostKey}, name: id + ".kycap"}
	u := url.URL{Scheme: t.Type}
	switch t.Type {
	case "local":
		dir, err := filepath.Abs(t.Endpoint)
		if err != nil {
			return l, errors.New("invalid local directory")
		}
		u.Scheme = "file"
		u.Path = filepath.ToSlash(dir)
		l.config = offsite.Config{}
	case "s3":
		u.Host = t.Bucket
		l.name = strings.TrimPrefix(t.Prefix, "/") + l.name
		l.config.S3Endpoint = t.Endpoint
		l.config.S3Region = t.Region
		if t.Endpoint != "" {
			ep, err := url.Parse(t.Endpoint)
			if err != nil || ep.Scheme != "https" || ep.Host == "" || ep.User != nil || ep.RawQuery != "" || ep.Fragment != "" {
				return l, errors.New("S3 endpoint must be HTTPS without credentials, query or fragment")
			}
			// Preserve the original endpoint rule exactly, including custom virtual-host targets.
			l.virtualS3 = strings.Contains(t.Endpoint, t.Bucket)
		}
	case "sftp":
		addr := t.Endpoint
		if _, _, err := net.SplitHostPort(addr); err != nil {
			addr = net.JoinHostPort(addr, "22")
		}
		u.Host = addr
		u.Path = "/" + strings.Trim(t.Prefix, "/")
		l.absoluteSFTP = strings.HasPrefix(t.Prefix, "/")
	case "smb":
		addr, share, dir, err := offsite.ParseSMBEndpoint(t.Endpoint, t.Bucket, t.Prefix)
		if err != nil {
			return l, err
		}
		u.Host = addr
		u.Path = "/" + share + "/" + dir
		sum := sha256.Sum256([]byte(id))
		l.name = fmt.Sprintf("kycap-v1-%x.kycap", sum)
	default:
		return l, errors.New("unsupported replication target type")
	}
	l.config.URL = u.String()
	// Validate names before a transfer, including retained compatibility paths.
	for _, part := range strings.Split(l.name, "/") {
		if part == "" || part == "." || part == ".." || strings.ContainsAny(part, "\\\x00") {
			return l, errors.New("invalid replica path")
		}
	}
	if strings.Contains(t.Endpoint, "@") {
		return l, errors.New("put credentials in dedicated fields, not the endpoint")
	}
	return l, nil
}

// matchesReplica consumes at most expected-size + 1 and closes the remote reader.
func matchesReplica(r io.ReadCloser, rec *db.CapsuleRecord) (result error) {
	defer func() { result = errors.Join(result, r.Close()) }()
	if rec.SizeBytes < 0 || len(rec.Digest) != 64 {
		return errors.New("capsule has no valid integrity receipt")
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(r, rec.SizeBytes+1))
	if err != nil {
		return err
	}
	if n != rec.SizeBytes || hex.EncodeToString(h.Sum(nil)) != rec.Digest {
		return errors.New("existing replica does not match capsule receipt; refusing replacement")
	}
	return nil
}

func (m *Manager) transfer(ctx context.Context, t db.ReplicationTargetRecord, rec *db.CapsuleRecord, f *os.File, size int64) error {
	l, err := targetLocation(t, rec.ID)
	if err != nil {
		return err
	}
	// ponytail: compatibility branches preserve targets v0.1.0 cannot express.
	// Remove them after a released library supports absolute SFTP and virtual-host S3.
	if l.absoluteSFTP {
		return NewSFTPClient(t.Endpoint, t.AccessKey, t.SecretKey, t.Prefix, t.HostKey).Put(ctx, l.name, f)
	}
	if l.virtualS3 {
		return NewS3Client(t.Endpoint, t.Bucket, t.Region, t.AccessKey, t.SecretKey).PutObject(ctx, l.name, f, size, "application/octet-stream")
	}
	target, err := offsite.Parse(l.config)
	if err != nil {
		return err
	}
	if t.Type == "smb" {
		// A historical replica may already exist under the original mixed-case ID.
		r, err := target.Get(ctx, l.name)
		if errors.Is(err, os.ErrNotExist) {
			r, err = newLegacySMB(t).get(ctx, rec.ID+".kycap")
		}
		if err == nil {
			return matchesReplica(r, rec)
		}
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	err = target.Put(ctx, l.name, f, size)
	if errors.Is(err, offsite.ErrObjectExists) {
		r, getErr := target.Get(ctx, l.name)
		if getErr != nil {
			return getErr
		}
		return matchesReplica(r, rec)
	}
	return err
}

// ValidateTarget checks stored fields without dialing or serializing credentials.
func ValidateTarget(t db.ReplicationTargetRecord) error {
	l, err := targetLocation(t, "connectivity-test")
	if err != nil {
		return err
	}
	_, err = offsite.Parse(l.config)
	return err
}
