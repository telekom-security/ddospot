// Package ntp implements the NTP service on UDP port 123 as the ntpd of a
// persona answers it: mode 3 client requests, mode 6 READVAR and, for
// ntpd releases that still have it, the mode 7 monitor list.
package ntp

import (
	"encoding/binary"
	"math/rand"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/t3chn0m4g3/ddospot/internal/limit"
	"github.com/t3chn0m4g3/ddospot/internal/persona"
	"github.com/t3chn0m4g3/ddospot/internal/udp"
)

// Port is the well-known port of the service.
const Port = 123

const (
	modeUnspec  = 0
	modeClient  = 3
	modeServer  = 4
	modeControl = 6
	modePrivate = 7

	// ntp.h NTP_OLDVERSION / NTP_VERSION.
	oldVersion = 1
	version    = 4

	// ntp.h NTP_MINPOLL: ntp_minpoll of ntp_monitor.c, the "mintc" of
	// READVAR and the lower bound of the poll in a server answer.
	minPoll = 3

	// Seconds between 1900 (NTP era 0) and 1970.
	ntpEpoch = 2208988800
)

// host holds the values of one ntpd that stay the same between answers.
type host struct {
	p     *persona.Persona
	old   bool   // ntpd 4.2.6
	assoc uint16 // association ID of the system peer
	freq  float64
	mon   []monPeer
}

// newHost rolls the values of one ntpd, with the monitor list as it is
// at now.
func newHost(p *persona.Persona, r *rand.Rand, now time.Time) host {
	h := host{p: p, old: strings.HasPrefix(p.NTP.ReadvarVersion, "ntpd 4.2.6")}
	// ntp_peer.c init_peer: the first association ID is random, each
	// configured server or pool takes the next one. 4.2.6 personas have
	// four server lines; 4.2.8 personas four pool lines, whose servers
	// follow them.
	base := uint16(1 + r.Intn(0xffff))
	if h.old {
		h.assoc = base + uint16(r.Intn(4))
	} else {
		h.assoc = base + 4 + uint16(r.Intn(8))
	}
	if h.assoc == 0 {
		h.assoc = 1
	}
	h.freq = (r.Float64()*2 - 1) * 40
	h.mon = rollMonitor(p, r, now)
	return h
}

// Answer builds the datagrams for one request, nil = no answer. Pure
// function, no I/O: the values that a server keeps between requests are
// rolled from rng.
func Answer(p *persona.Persona, req []byte, src netip.AddrPort, now time.Time, rng *rand.Rand) (resp [][]byte, mode string) {
	h := newHost(p, rng, now)
	return h.answer(req, src, now, func() time.Time { return reftimeAt(now, p.NTP.PollLog, rollStepJitter(rng)) }, rng)
}

// answer dispatches on the mode of the request (ntp_proto.c receive).
func (h *host) answer(req []byte, src netip.AddrPort, now time.Time, ref func() time.Time, r *rand.Rand) ([][]byte, string) {
	// receive: a packet from port 0 or shorter than 2 bytes is dropped.
	if len(req) < 2 || src.Port() == 0 {
		return nil, ""
	}
	vn := req[0] >> 3 & 7
	switch req[0] & 7 {
	case modeClient:
		if d := h.mode3(req, now, ref, r); d != nil {
			return [][]byte{d}, "DATA"
		}
	case modeUnspec:
		// receive: mode 0 of version 1 is a client request.
		if vn == oldVersion {
			if d := h.mode3(req, now, ref, r); d != nil {
				return [][]byte{d}, "DATA"
			}
		}
	case modeControl:
		if d := h.mode6(req, now, ref, r); d != nil {
			return d, "CONTROL"
		}
	case modePrivate:
		if d := h.mode7(req, src, now); d != nil {
			return d, "MONLIST"
		}
	}
	return nil, ""
}

// Server answers NTP requests within the budgets of its limiter.
type Server struct {
	conn *net.UDPConn
	lim  *limit.Limiter

	mu    sync.Mutex // guards rng, steps and h
	rng   *rand.Rand
	steps map[int64]time.Duration // reftime jitter per poll step
	h     host
}

// New returns a Server reading from conn that answers as persona p.
func New(conn *net.UDPConn, lim *limit.Limiter, p *persona.Persona) *Server {
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	return &Server{
		conn:  conn,
		lim:   lim,
		rng:   rng,
		steps: map[int64]time.Duration{},
		h:     newHost(p, rng, time.Now()),
	}
}

// Serve answers datagrams until the connection is closed.
func (s *Server) Serve() error {
	return udp.Loop(s.conn, s.handle)
}

func (s *Server) handle(req []byte, src netip.AddrPort) {
	resp, mode := s.answer(req, src, time.Now())
	if resp == nil {
		return
	}
	sum := 0
	for _, d := range resp {
		sum += len(d)
	}
	sample := limit.Sample{Transport: "udp", Req: req, RespSize: sum, Fields: map[string]any{"mode": mode}}
	if !s.lim.Admit(limit.NTP, src, sample, len(resp), sum) {
		return
	}
	for _, d := range resp {
		s.conn.WriteToUDPAddrPort(d, src)
	}
}

func (s *Server) answer(req []byte, src netip.AddrPort, now time.Time) ([][]byte, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.h.answer(req, src, now, func() time.Time { return s.reftimeLocked(now) }, s.rng)
}

// reftime returns the reference time of the persona's ntpd at now: the
// last clock update, once per poll interval.
func (s *Server) reftime(now time.Time) time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.reftimeLocked(now)
}

func (s *Server) reftimeLocked(now time.Time) time.Time {
	poll := s.h.p.NTP.PollLog
	step := now.Unix() >> poll
	j, ok := s.steps[step]
	if !ok {
		j = rollStepJitter(s.rng)
		for k := range s.steps {
			if k != step-1 {
				delete(s.steps, k)
			}
		}
		s.steps[step] = j
	}
	return reftimeAt(now, poll, j)
}

// reftimeAt is the start of the poll step of now, 2^poll seconds long,
// less the jitter of that step.
func reftimeAt(now time.Time, poll uint8, jitter time.Duration) time.Time {
	return time.Unix(now.Unix()>>poll<<poll, 0).Add(-jitter)
}

func rollStepJitter(r *rand.Rand) time.Duration {
	return time.Duration(r.Int63n(int64(2*time.Second) + 1))
}

// putStamp writes t as a 64-bit NTP timestamp. The bits of the fraction
// below the precision are random, as get_systime (libntp/systime.c)
// fills them.
func putStamp(b []byte, t time.Time, precision int8, r *rand.Rand) {
	sec, frac := stamp64(t)
	if precision < 0 && precision > -32 {
		mask := uint32(1)<<(32+int(precision)) - 1
		frac = frac&^mask | uint32(r.Int63())&mask
	}
	binary.BigEndian.PutUint32(b, sec)
	binary.BigEndian.PutUint32(b[4:], frac)
}

func stamp64(t time.Time) (sec, frac uint32) {
	return uint32(t.Unix() + ntpEpoch), uint32(uint64(t.Nanosecond()) << 32 / 1e9)
}

// jitter returns v changed by up to ±10 %.
func jitter(v float64, r *rand.Rand) float64 {
	return v * (0.9 + 0.2*r.Float64())
}
