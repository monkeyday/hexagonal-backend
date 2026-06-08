package smtp

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"testing"
)

// fakeServer runs a minimal SMTP server on a random local port.
// Each call to serveOne handles exactly one SMTP session (EHLO → MAIL → RCPT → DATA → RSET)
// and then closes the server-side connection.
type fakeServer struct {
	ln net.Listener
}

func newFakeServer(t *testing.T) *fakeServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	return &fakeServer{ln: ln}
}

func (s *fakeServer) addr() string { return s.ln.Addr().String() }
func (s *fakeServer) close()       { s.ln.Close() }

// serveOne spawns a goroutine that accepts one connection, handles one complete
// SMTP session (greeting → EHLO → MAIL → RCPT → DATA → RSET), then closes the
// server-side conn. If keepAlive is true the connection stays open. done is
// signalled when the session finishes.
func (s *fakeServer) serveOne(t *testing.T, keepAlive bool, done chan<- struct{}) {
	t.Helper()
	go func() {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		defer func() {
			if !keepAlive {
				conn.Close()
			}
			if done != nil {
				done <- struct{}{}
			}
		}()

		r := bufio.NewReader(conn)
		writeLine := func(s string) { fmt.Fprint(conn, s+"\r\n") }
		readLine := func() string {
			line, _ := r.ReadString('\n')
			return line
		}

		writeLine("220 localhost SMTP")
		readLine()                 // EHLO
		writeLine("250 localhost") // no extensions → no STARTTLS path
		readLine()                 // MAIL FROM
		writeLine("250 OK")
		readLine() // RCPT TO
		writeLine("250 OK")
		readLine() // DATA
		writeLine("354 Send message")
		for {
			line := readLine()
			if line == ".\r\n" {
				break
			}
		}
		writeLine("250 OK")
		readLine() // RSET
		writeLine("250 OK")
	}()
}

func TestClientSend(t *testing.T) {
	srv := newFakeServer(t)
	defer srv.close()

	done := make(chan struct{}, 1)
	srv.serveOne(t, false, done)

	c := NewClient(srv.addr(), "from@test.com")
	msg := BuildMessage("from@test.com", "to@test.com", "Test", "hello")
	if err := c.Send([]string{"to@test.com"}, msg); err != nil {
		t.Fatalf("send: %v", err)
	}
	<-done
	_ = c.Close()
}

func TestClientDoesNotRetryAfterDATA(t *testing.T) {
	srv := newFakeServer(t)
	defer srv.close()

	// Serve one session that rejects the message after receiving the full body.
	go func() {
		conn, err := srv.ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		r := bufio.NewReader(conn)
		writeLine := func(s string) { fmt.Fprint(conn, s+"\r\n") }
		readLine := func() string { line, _ := r.ReadString('\n'); return line }

		writeLine("220 localhost SMTP")
		readLine()                 // EHLO
		writeLine("250 localhost") // no extensions
		readLine()                 // MAIL FROM
		writeLine("250 OK")
		readLine() // RCPT TO
		writeLine("250 OK")
		readLine() // DATA
		writeLine("354 Send message")
		for readLine() != ".\r\n" {
		}
		writeLine("550 Message rejected") // server rejects after receiving full body
	}()

	c := NewClient(srv.addr(), "from@test.com")
	msg := BuildMessage("from@test.com", "to@test.com", "Test", "hello")

	err := c.Send([]string{"to@test.com"}, msg)
	if err == nil {
		t.Fatal("expected error from server rejection, got nil")
	}
	if !errors.Is(err, errDataSent) {
		t.Fatalf("want errDataSent, got: %v", err)
	}
	_ = c.Close()
}

func TestClientReconnectsOnDeadConnection(t *testing.T) {
	srv := newFakeServer(t)
	defer srv.close()

	// First connection: serve one send, then close server-side → client conn goes dead.
	dead := make(chan struct{}, 1)
	srv.serveOne(t, false, dead)

	c := NewClient(srv.addr(), "from@test.com")
	msg := BuildMessage("from@test.com", "to@test.com", "Test", "hello")

	if err := c.Send([]string{"to@test.com"}, msg); err != nil {
		t.Fatalf("first send: %v", err)
	}
	<-dead // wait for server to close its side

	// Second connection: serve one send.
	done := make(chan struct{}, 1)
	srv.serveOne(t, false, done)

	// Client still holds the dead conn. Second send must reconnect automatically.
	if err := c.Send([]string{"to@test.com"}, msg); err != nil {
		t.Fatalf("send after reconnect: %v", err)
	}
	<-done
	_ = c.Close()
}
