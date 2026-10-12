// Package chargen implements the character generator service on UDP port 19.
package chargen

import (
	"net"
	"net/netip"
	"sync/atomic"

	"github.com/t3chn0m4g3/ddospot/internal/limit"
	"github.com/t3chn0m4g3/ddospot/internal/udp"
)

const (
	// Port is the well-known port of the service.
	Port = 19
	// Size is the length of every answer.
	Size = 1024

	lineLen  = 72
	firstCh  = 33
	charSpan = 95
)

// Response returns one answer: lines of 72 printable characters ended by
// CRLF, cut to Size bytes. The first character of line i is the character
// at position offset+i of the cyclic range 33..126.
func Response(offset int) []byte {
	start := (offset%charSpan + charSpan) % charSpan
	out := make([]byte, 0, Size+lineLen+2)
	for i := 0; len(out) < Size; i++ {
		for j := 0; j < lineLen; j++ {
			out = append(out, byte(firstCh+(start+i+j)%charSpan))
		}
		out = append(out, '\r', '\n')
	}
	return out[:Size]
}

// Server answers every datagram within the budgets of its limiter.
type Server struct {
	conn *net.UDPConn
	lim  *limit.Limiter
	off  atomic.Uint32
}

// New returns a Server reading from conn.
func New(conn *net.UDPConn, lim *limit.Limiter) *Server {
	return &Server{conn: conn, lim: lim}
}

// Serve answers datagrams until the connection is closed.
func (s *Server) Serve() error {
	return udp.Loop(s.conn, s.handle)
}

func (s *Server) handle(req []byte, src netip.AddrPort) {
	sample := limit.Sample{Transport: "udp", Req: req, RespSize: Size, Fields: map[string]any{}}
	if !s.lim.Admit(limit.Chargen, src, sample, 1, Size) {
		return
	}
	o := s.off.Add(1) - 1
	s.conn.WriteToUDPAddrPort(Response(int(o)), src)
}
