package dnspot

import (
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

// acceptAll accepts on l until it is closed and hands out the connections.
func acceptAll(t *testing.T, l net.Listener) <-chan net.Conn {
	t.Helper()
	ch := make(chan net.Conn, 16)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				close(ch)
				return
			}
			ch <- c
		}
	}()
	t.Cleanup(func() { l.Close() })
	return ch
}

func dial(t *testing.T, addr string) net.Conn {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// closedByPeer reports whether the other end closed c.
func closedByPeer(c net.Conn) bool {
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, err := c.Read(make([]byte, 1))
	return errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) || isReset(err)
}

func isReset(err error) bool {
	var op *net.OpError
	return errors.As(err, &op) && !op.Timeout()
}

func accepted(t *testing.T, ch <-chan net.Conn) net.Conn {
	t.Helper()
	select {
	case c := <-ch:
		return c
	case <-time.After(2 * time.Second):
		t.Fatal("connection not accepted")
		return nil
	}
}

func TestLimitListenerPerAddr(t *testing.T) {
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	l := LimitListener(raw, 10, 2).(*capListener)
	ch := acceptAll(t, l)
	addr := raw.Addr().String()
	dial(t, addr)
	dial(t, addr)
	s1 := accepted(t, ch)
	accepted(t, ch)
	if !closedByPeer(dial(t, addr)) {
		t.Fatal("third connection of one address kept open")
	}
	if l.Open() != 2 {
		t.Fatalf("open = %d, want 2", l.Open())
	}
	s1.Close()
	s1.Close()
	if l.Open() != 1 {
		t.Fatalf("open after close = %d, want 1", l.Open())
	}
	dial(t, addr)
	accepted(t, ch)
}

func TestLimitListenerTotal(t *testing.T) {
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	l := LimitListener(raw, 2, 10).(*capListener)
	ch := acceptAll(t, l)
	addr := raw.Addr().String()
	dial(t, addr)
	dial(t, addr)
	accepted(t, ch)
	accepted(t, ch)
	if !closedByPeer(dial(t, addr)) {
		t.Fatal("connection beyond the total kept open")
	}
}
