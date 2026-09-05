package replication

import (
	"context"
	"fmt"
	"github.com/Busness-app/ky-primitives/offsite"
	"github.com/Busness-app/kyrecovery-server/internal/db"
	"io"
	"net"
	"os"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/hirochachacha/go-smb2"
)

// legacySMBClient reads historical capsules from a share. go-smb2 only speaks SMB 2 and 3, so
// SMB1 is never negotiated, and this client requires signing rather than
// leaving it to the server. Known gap: go-smb2 trusts a server that declares
// the session guest and then accepts its responses unsigned, so an
// impersonating server can swallow uploads. See README.
type legacySMBClient struct {
	Addr    string // host or host:port, port defaults to 445
	Share   string
	User    string // user or DOMAIN\user
	Secret  string
	Dir     string
	Timeout time.Duration // whole-operation budget; zero means defaultTransferBudget
	err     error         // endpoint rejected by ParseSMBEndpoint; reported on dial
}

// ParseSMBEndpoint accepts a bare host, host:port, or the forms an operator
// copies from a file manager: \\host\share\dir, //host/share/dir or
// smb://host/share/dir. A share or directory in the path fills in whichever of
// share and dir was left blank. Userinfo is refused: a pasted
// smb://user:password@host would put the password in the cleartext endpoint.
func ParseSMBEndpoint(endpoint, share, dir string) (string, string, string, error) {
	return offsite.ParseSMBEndpoint(endpoint, share, dir)
}

func newLegacySMB(t db.ReplicationTargetRecord) *legacySMBClient {
	addr, share, dir, err := ParseSMBEndpoint(t.Endpoint, t.Bucket, t.Prefix)
	return &legacySMBClient{Addr: addr, Share: share, User: t.AccessKey, Secret: t.SecretKey, Dir: dir, err: err}
}

// mount returns the mounted share and a cleanup that logs off and closes. The
// connection is torn down when ctx ends, which unblocks any stalled I/O.
func (c *legacySMBClient) mount(ctx context.Context) (*smb2.Share, func(), error) {
	if c.err != nil {
		return nil, nil, c.err
	}
	domain, user, _ := strings.Cut(c.User, "\\")
	if user == "" { // no backslash: Cut put the whole thing in domain
		domain, user = "", domain
	}
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", c.Addr)
	if err != nil {
		return nil, nil, err
	}
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	cleanup := func() { stop(); conn.Close() }

	d := &smb2.Dialer{
		Negotiator: smb2.Negotiator{RequireMessageSigning: true},
		Initiator:  &smb2.NTLMInitiator{User: user, Password: c.Secret, Domain: domain},
	}
	sess, err := d.DialContext(ctx, conn)
	if err != nil {
		cleanup()
		return nil, nil, err
	}
	share, err := sess.Mount(c.Share)
	if err != nil {
		sess.Logoff()
		cleanup()
		return nil, nil, fmt.Errorf("mount %s: %w", c.Share, err)
	}
	return share, func() { share.Umount(); sess.Logoff(); cleanup() }, nil
}

func (c *legacySMBClient) budget(ctx context.Context) (context.Context, context.CancelFunc) {
	t := c.Timeout
	if t == 0 {
		t = defaultTransferBudget
	}
	return context.WithTimeout(ctx, t)
}

// Only historical capsule basenames can enter the compatibility reader. It has
// no write path and cannot address ADS, separators, Windows devices or short names.
var legacySMBName = regexp.MustCompile(`^cap-[A-Za-z0-9_.-]+\.kycap$`)

func (c *legacySMBClient) get(ctx context.Context, name string) (io.ReadCloser, error) {
	if !legacySMBName.MatchString(name) {
		// Outside the legacy namespace: the canonical writer may still accept it.
		return nil, os.ErrNotExist
	}
	ctx, cancel := c.budget(ctx)
	share, cleanup, err := c.mount(ctx)
	if err != nil {
		cancel()
		return nil, err
	}
	f, err := share.Open(path.Join(c.Dir, name))
	if err != nil {
		cleanup()
		cancel()
		if os.IsNotExist(err) {
			return nil, os.ErrNotExist
		}
		return nil, err
	}
	return &legacySMBReader{ReadCloser: f, cleanup: func() { cleanup(); cancel() }}, nil
}

type legacySMBReader struct {
	io.ReadCloser
	cleanup func()
}

func (r *legacySMBReader) Close() error { err := r.ReadCloser.Close(); r.cleanup(); return err }
