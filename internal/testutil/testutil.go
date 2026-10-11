// Package testutil holds helpers shared by the tests of the pots.
package testutil

import (
	"net"
	"testing"
	"time"

	"github.com/t3chn0m4g3/ddospot/internal/limit"
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
