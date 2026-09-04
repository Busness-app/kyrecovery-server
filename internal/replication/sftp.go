package replication

import (
	"context"
	"fmt"
	"io"
	"net"
	"path"
	"strings"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

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
	HostKey string // "SHA256:..." as printed by ssh-keygen -l
}

func NewSFTPClient(addr, user, secret, dir, hostKey string) *SFTPClient {
	if _, _, err := net.SplitHostPort(addr); err != nil {
		addr = net.JoinHostPort(addr, "22")
	}
	return &SFTPClient{Addr: addr, User: user, Secret: secret, Dir: strings.TrimSuffix(dir, "/"), HostKey: hostKey}
}

func (c *SFTPClient) dial() (*ssh.Client, *sftp.Client, error) {
	var auth ssh.AuthMethod
	if strings.HasPrefix(c.Secret, "-----BEGIN") {
		signer, err := ssh.ParsePrivateKey([]byte(c.Secret))
		if err != nil {
			return nil, nil, fmt.Errorf("private key: %w", err)
		}
		auth = ssh.PublicKeys(signer)
	} else {
		auth = ssh.Password(c.Secret)
	}
	cfg := &ssh.ClientConfig{
		User:    c.User,
		Auth:    []ssh.AuthMethod{auth},
		Timeout: 60 * time.Second,
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
	conn, err := ssh.Dial("tcp", c.Addr, cfg)
	if err != nil {
		return nil, nil, err
	}
	client, err := sftp.NewClient(conn)
	if err != nil {
		conn.Close()
		return nil, nil, err
	}
	return conn, client, nil
}

// Put streams data to Dir/name, creating Dir if needed.
func (c *SFTPClient) Put(ctx context.Context, name string, data io.Reader) error {
	conn, client, err := c.dial()
	if err != nil {
		return err
	}
	defer conn.Close()
	defer client.Close()
	if err := client.MkdirAll(c.Dir); err != nil {
		return err
	}
	f, err := client.Create(path.Join(c.Dir, name))
	if err != nil {
		return err
	}
	if _, err := f.ReadFrom(data); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// TestConnection authenticates and proves Dir is writable.
func (c *SFTPClient) TestConnection(ctx context.Context) error {
	conn, client, err := c.dial()
	if err != nil {
		return err
	}
	defer conn.Close()
	defer client.Close()
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
