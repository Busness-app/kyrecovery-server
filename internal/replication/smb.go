package replication

import (
	"context"
	"fmt"
	"io"
	"net"
	"path"
	"strings"
	"time"

	"github.com/hirochachacha/go-smb2"
)

// SMBClient uploads capsules to a share. go-smb2 only speaks SMB 2 and 3, so
// SMB1 is never negotiated, and this client requires signing rather than
// leaving it to the server. Known gap: go-smb2 trusts a server that declares
// the session guest and then accepts its responses unsigned, so an
// impersonating server can swallow uploads. See README.
type SMBClient struct {
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
func ParseSMBEndpoint(endpoint, share, dir string) (addr, outShare, outDir string, err error) {
	addr = strings.ReplaceAll(endpoint, "\\", "/")
	if len(addr) >= 6 && strings.EqualFold(addr[:6], "smb://") {
		addr = addr[6:]
	}
	addr = strings.TrimLeft(addr, "/")
	// Before any split: a password may itself contain "/" or "\", and the
	// endpoint column is cleartext. A share named with "@" loses out; the
	// message says where the user and password belong.
	if strings.Contains(addr, "@") {
		return "", "", "", fmt.Errorf("SMB host %q carries a username or password; put the user in the username field and the password in the password field", endpoint)
	}
	if host, rest, ok := strings.Cut(addr, "/"); ok {
		addr = host
		pathShare, pathDir, _ := strings.Cut(strings.Trim(rest, "/"), "/")
		if share == "" {
			share = pathShare
		}
		if dir == "" {
			dir = pathDir
		}
	}
	if _, _, err := net.SplitHostPort(addr); err != nil {
		addr = net.JoinHostPort(addr, "445")
	}
	return addr, share, strings.Trim(dir, "/"), nil
}

// NewSMBClient builds a client from a target's stored fields. Endpoints are
// validated with ParseSMBEndpoint when the target is saved; a value that still
// fails here yields a client whose dial reports the error.
func NewSMBClient(addr, share, user, secret, dir string) *SMBClient {
	a, sh, d, err := ParseSMBEndpoint(addr, share, dir)
	return &SMBClient{Addr: a, Share: sh, User: user, Secret: secret, Dir: d, err: err}
}

// mount returns the mounted share and a cleanup that logs off and closes. The
// connection is torn down when ctx ends, which unblocks any stalled I/O.
func (c *SMBClient) mount(ctx context.Context) (*smb2.Share, func(), error) {
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

func (c *SMBClient) budget(ctx context.Context) (context.Context, context.CancelFunc) {
	t := c.Timeout
	if t == 0 {
		t = defaultTransferBudget
	}
	return context.WithTimeout(ctx, t)
}

// Put streams data to Dir/name inside the share, creating Dir if needed. The
// bytes land in a temporary name and are renamed into place, so an aborted
// transfer never replaces a complete replica with a short one.
func (c *SMBClient) Put(ctx context.Context, name string, data io.Reader) error {
	ctx, cancel := c.budget(ctx)
	defer cancel()
	share, cleanup, err := c.mount(ctx)
	if err != nil {
		return err
	}
	defer cleanup()
	if c.Dir != "" {
		if err := share.MkdirAll(c.Dir, 0700); err != nil {
			return err
		}
	}
	final := path.Join(c.Dir, name)
	tmp := final + ".part"
	f, err := share.Create(tmp)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, data); err != nil {
		f.Close()
		share.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		share.Remove(tmp)
		return err
	}
	share.Remove(final) // SMB rename does not replace an existing file
	return share.Rename(tmp, final)
}

// TestConnection authenticates, mounts the share and proves Dir is writable.
func (c *SMBClient) TestConnection(ctx context.Context) error {
	ctx, cancel := c.budget(ctx)
	defer cancel()
	share, cleanup, err := c.mount(ctx)
	if err != nil {
		return err
	}
	defer cleanup()
	if c.Dir != "" {
		if err := share.MkdirAll(c.Dir, 0700); err != nil {
			return err
		}
	}
	probe := path.Join(c.Dir, ".kyrecovery-ping")
	if err := share.WriteFile(probe, []byte("ping"), 0600); err != nil {
		return err
	}
	return share.Remove(probe)
}
