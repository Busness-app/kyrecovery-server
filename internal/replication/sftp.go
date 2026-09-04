package replication

import (
	"context"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"path"
	"strings"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

// defaultTransferBudget bounds one whole Put or TestConnection, dial included.
// A target that accepts the TCP connection and then stalls must not pin a
// goroutine and the capsule's file handle forever.
const defaultTransferBudget = 5 * time.Minute

// UnknownHostKeyError is returned when a target has no pinned host key. It
// carries the server's fingerprint so the operator can pin it deliberately.
type UnknownHostKeyError struct{ Fingerprint string }

func (e *UnknownHostKeyError) Error() string {
	return "host key not pinned; server presented " + e.Fingerprint
}

// SFTPClient uploads capsules over SSH. The server's host key must match the
// pinned SHA256 fingerprint; a blank pin never connects.
type SFTPClient struct {
	Addr    string // host or host:port, port defaults to 22
	User    string
	Secret  string // password, or a PEM private key
	Dir     string
	HostKey string        // "SHA256:..." as printed by ssh-keygen -l
	Timeout time.Duration // whole-operation budget; zero means defaultTransferBudget
}

func NewSFTPClient(addr, user, secret, dir, hostKey string) *SFTPClient {
	if _, _, err := net.SplitHostPort(addr); err != nil {
		addr = net.JoinHostPort(addr, "22")
	}
	return &SFTPClient{Addr: addr, User: user, Secret: secret, Dir: strings.TrimSuffix(dir, "/"), HostKey: hostKey}
}

// auth picks key or password by PEM structure, never by prefix: a private key
// with stray leading whitespace must not be sent to the server as a password.
func (c *SFTPClient) auth() (ssh.AuthMethod, error) {
	if block, _ := pem.Decode([]byte(c.Secret)); block != nil {
		signer, err := ssh.ParsePrivateKey([]byte(c.Secret))
		if err != nil {
			return nil, fmt.Errorf("private key: %w", err)
		}
		return ssh.PublicKeys(signer), nil
	}
	return ssh.Password(c.Secret), nil
}

// dial returns a connected SFTP session and a cleanup that closes it. The
// connection is torn down when ctx ends, which unblocks any stalled I/O.
func (c *SFTPClient) dial(ctx context.Context) (*sftp.Client, func(), error) {
	auth, err := c.auth()
	if err != nil {
		return nil, nil, err
	}
	cfg := &ssh.ClientConfig{
		User: c.User,
		Auth: []ssh.AuthMethod{auth},
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			fp := ssh.FingerprintSHA256(key)
			if c.HostKey == "" {
				return &UnknownHostKeyError{Fingerprint: fp}
			}
			if fp != c.HostKey {
				return fmt.Errorf("host key mismatch: pinned %s, server presented %s", c.HostKey, fp)
			}
			return nil
		},
	}
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", c.Addr)
	if err != nil {
		return nil, nil, err
	}
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	cleanup := func() { stop(); conn.Close() }

	sconn, chans, reqs, err := ssh.NewClientConn(conn, c.Addr, cfg)
	if err != nil {
		cleanup()
		return nil, nil, err
	}
	client, err := sftp.NewClient(ssh.NewClient(sconn, chans, reqs))
	if err != nil {
		cleanup()
		return nil, nil, err
	}
	return client, func() { client.Close(); cleanup() }, nil
}

func (c *SFTPClient) budget(ctx context.Context) (context.Context, context.CancelFunc) {
	t := c.Timeout
	if t == 0 {
		t = defaultTransferBudget
	}
	return context.WithTimeout(ctx, t)
}

// Put streams data to Dir/name, creating Dir if needed. The bytes land in a
// temporary name and are renamed into place, so an aborted transfer never
// replaces a complete replica with a short one.
func (c *SFTPClient) Put(ctx context.Context, name string, data io.Reader) error {
	ctx, cancel := c.budget(ctx)
	defer cancel()
	client, cleanup, err := c.dial(ctx)
	if err != nil {
		return err
	}
	defer cleanup()
	if err := client.MkdirAll(c.Dir); err != nil {
		return err
	}
	final := path.Join(c.Dir, name)
	tmp := final + ".part"
	f, err := client.Create(tmp)
	if err != nil {
		return err
	}
	if _, err := f.ReadFrom(data); err != nil {
		f.Close()
		client.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		client.Remove(tmp)
		return err
	}
	return client.PosixRename(tmp, final)
}

// TestConnection authenticates and proves Dir is writable.
func (c *SFTPClient) TestConnection(ctx context.Context) error {
	ctx, cancel := c.budget(ctx)
	defer cancel()
	client, cleanup, err := c.dial(ctx)
	if err != nil {
		return err
	}
	defer cleanup()
	if err := client.MkdirAll(c.Dir); err != nil {
		return err
	}
	probe := path.Join(c.Dir, ".kyrecovery-ping")
	f, err := client.Create(probe)
	if err != nil {
		return err
	}
	f.Close()
	return client.Remove(probe)
}
