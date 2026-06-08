package smtp

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/smtp"
	"strings"
	"sync"
	"time"
)

// errDataSent marks errors that occurred after the message body was transmitted.
// Retrying after this point risks sending a duplicate email because the server
// may already have accepted the message. Send detects this sentinel and does not
// retry.
var errDataSent = errors.New("smtp: message body already sent — retry would risk duplicate delivery")

const (
	dialTimeout = 10 * time.Second
	sendTimeout = 30 * time.Second
)

// Client maintains a persistent connection to an SMTP relay.
// It supports opportunistic STARTTLS, enforces I/O deadlines on every send,
// and reconnects automatically on failure (one retry per call).
type Client struct {
	From string // SMTP envelope sender and From header
	addr string // host:port

	mu   sync.Mutex
	conn *smtp.Client
	raw  net.Conn // kept for SetDeadline — survives TLS upgrade
}

func NewClient(addr, from string) *Client {
	return &Client{addr: addr, From: from}
}

// Send transmits rawMsg to the given recipients using the persistent connection.
// rawMsg must be a valid RFC 2822 message including all headers.
//
// Retry policy: pre-DATA errors (connection dead before body is written) trigger
// one reconnect and retry. Post-DATA errors (body already transmitted) are
// returned immediately without retry to avoid duplicate delivery.
func (c *Client) Send(to []string, rawMsg []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn == nil {
		if err := c.dial(); err != nil {
			return err
		}
	}

	err := c.doSend(to, rawMsg)
	if err == nil {
		return nil
	}

	c.closeConn()

	// Post-DATA: server may already have accepted the message; do not retry.
	if errors.Is(err, errDataSent) {
		return err
	}

	// Pre-DATA: safe to reconnect and retry once.
	if dialErr := c.dial(); dialErr != nil {
		return dialErr
	}
	return c.doSend(to, rawMsg)
}

// Close gracefully quits the SMTP session and closes the TCP connection.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closeConn()
	return nil
}

func (c *Client) doSend(to []string, rawMsg []byte) error {
	_ = c.raw.SetDeadline(time.Now().Add(sendTimeout))
	defer func() { _ = c.raw.SetDeadline(time.Time{}) }()

	if err := c.conn.Mail(c.From); err != nil {
		return fmt.Errorf("MAIL FROM: %w", err)
	}
	for _, r := range to {
		if err := c.conn.Rcpt(r); err != nil {
			return fmt.Errorf("RCPT TO %s: %w", r, err)
		}
	}
	wc, err := c.conn.Data()
	if err != nil {
		return fmt.Errorf("DATA: %w", err)
	}
	// Body transmission begins here. Errors from this point forward are wrapped
	// with errDataSent so Send does not retry and risk duplicate delivery.
	if _, err = wc.Write(rawMsg); err != nil {
		_ = wc.Close()
		return fmt.Errorf("%w: write body: %v", errDataSent, err)
	}
	if err := wc.Close(); err != nil {
		return fmt.Errorf("%w: end DATA: %v", errDataSent, err)
	}
	// reset envelope so the connection is ready for the next send
	_ = c.conn.Reset()
	return nil
}

func (c *Client) dial() error {
	host, _, _ := net.SplitHostPort(c.addr)

	raw, err := net.DialTimeout("tcp", c.addr, dialTimeout)
	if err != nil {
		return fmt.Errorf("smtp dial %s: %w", c.addr, err)
	}

	sc, err := smtp.NewClient(raw, host)
	if err != nil {
		_ = raw.Close()
		return fmt.Errorf("smtp handshake: %w", err)
	}

	// opportunistic STARTTLS — mirrors what smtp.SendMail does
	if ok, _ := sc.Extension("STARTTLS"); ok {
		cfg := &tls.Config{ServerName: host}
		if err := sc.StartTLS(cfg); err != nil {
			_ = sc.Close()
			_ = raw.Close()
			return fmt.Errorf("STARTTLS: %w", err)
		}
	}

	c.conn = sc
	c.raw = raw
	return nil
}

func (c *Client) closeConn() {
	if c.conn != nil {
		_ = c.conn.Close()
		c.conn = nil
		c.raw = nil
	}
}

// BuildMessage formats a minimal RFC 2822 email message.
// Callers that need more control can build the message themselves and call Send directly.
func BuildMessage(from, to, subject, body string) []byte {
	return []byte(fmt.Sprintf(
		"To: %s\r\nFrom: %s\r\nSubject: %s\r\n\r\n%s",
		to, from, subject, strings.TrimRight(body, "\r\n")+"\r\n",
	))
}
