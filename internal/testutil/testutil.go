// Package testutil holds helpers shared by the tests of the pots.
package testutil

import (
	"bufio"
	"encoding/json"
	"net"
	"os"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/telekom-security/ddospot/internal/limit"
)

// UDPPair returns a UDP socket listening on 127.0.0.1 and a client socket
// connected to it. Both are closed when the test ends.
func UDPPair(t *testing.T) (srv, cli *net.UDPConn) {
	t.Helper()
	srv, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	cli, err = net.DialUDP("udp", nil, srv.LocalAddr().(*net.UDPAddr))
	if err != nil {
		srv.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { cli.Close(); srv.Close() })
	return srv, cli
}

// ReadTimeout reads one datagram and returns its length, or 0 when nothing
// arrives within d.
func ReadTimeout(c *net.UDPConn, d time.Duration) int {
	buf := make([]byte, 65535)
	c.SetReadDeadline(time.Now().Add(d))
	n, err := c.Read(buf)
	c.SetReadDeadline(time.Time{})
	if err != nil {
		return 0
	}
	return n
}

// NopObs is a limit.Observer that ignores every event.
type NopObs struct{}

func (NopObs) Scanner(limit.Source)     {}
func (NopObs) TargetStart(limit.Source) {}
func (NopObs) TargetEnd(limit.Source)   {}
func (NopObs) NetStart(limit.Net)       {}
func (NopObs) NetEnd(limit.Net)         {}

// DNSRecorder is a dns.ResponseWriter that keeps the last written message.
type DNSRecorder struct {
	Remote net.Addr // returned by RemoteAddr
	Msg    *dns.Msg // the message given to WriteMsg, nil if none
}

func (r *DNSRecorder) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53}
}
func (r *DNSRecorder) RemoteAddr() net.Addr        { return r.Remote }
func (r *DNSRecorder) WriteMsg(m *dns.Msg) error   { r.Msg = m; return nil }
func (r *DNSRecorder) Write(b []byte) (int, error) { return len(b), nil }
func (r *DNSRecorder) Close() error                { return nil }
func (r *DNSRecorder) TsigStatus() error           { return nil }
func (r *DNSRecorder) TsigTimersOnly(bool)         {}
func (r *DNSRecorder) Hijack()                     {}

// ReadJSON reads a file of JSON lines into one map per line and fails the
// test on a line that is not a JSON object.
func ReadJSON(t *testing.T, path string) []map[string]any {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []map[string]any
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		var m map[string]any
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			t.Fatalf("line %q: %v", sc.Text(), err)
		}
		out = append(out, m)
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}
