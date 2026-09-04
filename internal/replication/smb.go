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
// SMB1 is never negotiated; the session is signed and encrypted when the
// share requires it.
type SMBClient struct {
	Addr   string // host or host:port, port defaults to 445
	Share  string
	User   string // user or DOMAIN\user
	Secret string
	Dir    string
}

func NewSMBClient(addr, share, user, secret, dir string) *SMBClient {
	if _, _, err := net.SplitHostPort(addr); err != nil {
		addr = net.JoinHostPort(addr, "445")
	}
	return &SMBClient{Addr: addr, Share: share, User: user, Secret: secret, Dir: strings.Trim(dir, "/")}
}

func (c *SMBClient) mount(ctx context.Context) (net.Conn, *smb2.Session, *smb2.Share, error) {
	domain, user, _ := strings.Cut(c.User, "\\")
	if user == "" { // no backslash: Cut put the whole thing in domain
		domain, user = "", domain
	}
	conn, err := (&net.Dialer{Timeout: 60 * time.Second}).DialContext(ctx, "tcp", c.Addr)
	if err != nil {
		return nil, nil, nil, err
	}
	d := &smb2.Dialer{Initiator: &smb2.NTLMInitiator{User: user, Password: c.Secret, Domain: domain}}
	sess, err := d.DialContext(ctx, conn)
	if err != nil {
		conn.Close()
		return nil, nil, nil, err
	}
	share, err := sess.Mount(c.Share)
	if err != nil {
		sess.Logoff()
		conn.Close()
		return nil, nil, nil, fmt.Errorf("mount %s: %w", c.Share, err)
	}
	return conn, sess, share, nil
}

// Put streams data to Dir/name inside the share, creating Dir if needed.
func (c *SMBClient) Put(ctx context.Context, name string, data io.Reader) error {
	conn, sess, share, err := c.mount(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	defer sess.Logoff()
	defer share.Umount()
	if c.Dir != "" {
		if err := share.MkdirAll(c.Dir, 0700); err != nil {
			return err
		}
	}
	f, err := share.Create(path.Join(c.Dir, name))
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, data); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// TestConnection authenticates, mounts the share and proves Dir is writable.
func (c *SMBClient) TestConnection(ctx context.Context) error {
	conn, sess, share, err := c.mount(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	defer sess.Logoff()
	defer share.Umount()
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
