// Package dnspot implements the DNS service on port 53 (UDP and TCP) as
// the name server of a persona answers it: CH TXT version.bind and
// hostname.bind from the persona, class IN recursively through an
// upstream resolver with a cache, answers sized per transport.
package dnspot

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/t3chn0m4g3/ddospot/internal/limit"
	"github.com/t3chn0m4g3/ddospot/internal/persona"
)

// Port is the well-known port of the service.
const Port = 53

const (
	anyTTL      = 3789 // TTL of the HINFO answer to ANY (RFC 8482)
	resolveTime = 3 * time.Second
)

// Handler answers DNS requests as persona p within the budgets of lim.
// It is safe for concurrent use.
type Handler struct {
	p     *persona.Persona
	lim   *limit.Limiter
	up    Upstream // nil = recursion off
	cache *cache
	now   func() time.Time
}

// NewHandler returns a Handler; up nil turns recursion off.
func NewHandler(p *persona.Persona, lim *limit.Limiter, up Upstream) *Handler {
	return &Handler{p: p, lim: lim, up: up, cache: newCache(maxEntries), now: time.Now}
}

// Accept is the MsgAcceptFunc for the dns.Server of the Handler: it
// drops responses and hands every request to the Handler, which answers
// FORMERR and NOTIMP within the budgets itself.
func Accept(dh dns.Header) dns.MsgAcceptAction {
	if dh.Bits&(1<<15) != 0 { // QR
		return dns.MsgIgnore
	}
	return dns.MsgAccept
}

// StrictReader is the DecorateReader for the dns.Server of the Handler:
// it drops messages that do not parse, so that none of them is answered
// outside the Handler. On TCP such a message ends the connection.
func StrictReader(r dns.Reader) dns.Reader { return strictReader{r} }

var errUnparsable = errors.New("dnspot: message does not parse")

type strictReader struct{ dns.Reader }

func parses(m []byte) bool { return new(dns.Msg).Unpack(m) == nil }

func (s strictReader) ReadTCP(conn net.Conn, timeout time.Duration) ([]byte, error) {
	m, err := s.Reader.ReadTCP(conn, timeout)
	if err == nil && !parses(m) {
		return nil, errUnparsable
	}
	return m, err
}

func (s strictReader) ReadUDP(conn *net.UDPConn, timeout time.Duration) ([]byte, *dns.SessionUDP, error) {
	for {
		m, sess, err := s.Reader.ReadUDP(conn, timeout)
		if err != nil || parses(m) {
			return m, sess, err
		}
	}
}

func (s strictReader) ReadPacketConn(conn net.PacketConn, timeout time.Duration) ([]byte, net.Addr, error) {
	pr, ok := s.Reader.(dns.PacketConnReader)
	if !ok {
		return nil, nil, errors.New("dnspot: reader without PacketConn support")
	}
	for {
		m, addr, err := pr.ReadPacketConn(conn, timeout)
		if err != nil || parses(m) {
			return m, addr, err
		}
	}
}

// source returns the client address and whether it came over TCP.
func source(a net.Addr) (netip.AddrPort, bool, bool) {
	switch a := a.(type) {
	case *net.UDPAddr:
		return a.AddrPort(), false, true
	case *net.TCPAddr:
		return a.AddrPort(), true, true
	case nil:
		return netip.AddrPort{}, false, false
	}
	ap, err := netip.ParseAddrPort(a.String())
	return ap, false, err == nil
}

// fields are the request fields of the log event.
func fields(r *dns.Msg) map[string]any {
	f := map[string]any{"opcode": r.Opcode}
	if len(r.Question) > 0 {
		q := r.Question[0]
		f["dns_name"] = q.Name
		f["dns_type"] = dns.Type(q.Qtype).String()
		f["dns_cls"] = dns.Class(q.Qclass).String()
	}
	return f
}

func (h *Handler) recursion() bool { return h.up != nil && h.up.Healthy() }

// ServeDNS answers one request. Every request is counted once by the
// limiter; a request that needs the upstream is counted before the
// upstream query, with the largest answer its transport allows.
func (h *Handler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	if r.Response {
		return
	}
	src, tcp, ok := source(w.RemoteAddr())
	if !ok {
		return
	}
	udp := !tcp
	transport := "udp"
	if tcp {
		transport = "tcp"
	}
	req, _ := r.Pack()
	sample := limit.Sample{Transport: transport, Req: req, Fields: fields(r)}

	resp, miss := h.build(r)
	if miss == nil {
		resp = Limit(resp, r, udp)
		if h.admit(src, sample, resp.Len(), udp) {
			w.WriteMsg(resp)
		}
		return
	}
	if !h.admit(src, sample, maxSize(r, udp), udp) {
		return
	}
	e, err := h.resolve(r.Question[0], *miss)
	if err != nil {
		return
	}
	fill(resp, r.Question[0], e)
	w.WriteMsg(Limit(resp, r, udp))
}

// admit counts one answer of size bytes. TCP answers are outside the
// global budget, which is kept for UDP.
func (h *Handler) admit(src netip.AddrPort, s limit.Sample, size int, udp bool) bool {
	s.RespSize = size
	datagrams, bytes := 0, 0
	if udp {
		datagrams, bytes = 1, size
	}
	return h.lim.Admit(limit.DNS, src, s, datagrams, bytes)
}

// build makes the answer to r from the persona and the cache. When the
// answer needs the upstream, it returns the header part of the answer
// and the cache key of the question.
func (h *Handler) build(r *dns.Msg) (*dns.Msg, *cacheKey) {
	resp := new(dns.Msg)
	resp.Id = r.Id
	resp.Response = true
	resp.Opcode = r.Opcode
	resp.RecursionDesired = r.RecursionDesired
	resp.CheckingDisabled = r.CheckingDisabled
	resp.RecursionAvailable = h.recursion()
	if len(r.Question) == 1 {
		resp.Question = []dns.Question{r.Question[0]}
	}
	if r.IsEdns0() != nil {
		o := &dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT}}
		o.SetUDPSize(h.p.DNS.EDNSSize)
		resp.Extra = []dns.RR{o}
	}

	switch {
	case r.Opcode != dns.OpcodeQuery:
		resp.Rcode = dns.RcodeNotImplemented
		return resp, nil
	case len(r.Question) != 1:
		resp.Rcode = dns.RcodeFormatError
		return resp, nil
	}
	q := r.Question[0]
	switch q.Qclass {
	case dns.ClassCHAOS:
		h.chaos(resp, q)
	case dns.ClassINET:
		if !resp.RecursionAvailable {
			resp.Rcode = dns.RcodeRefused
			break
		}
		if q.Qtype == dns.TypeANY {
			resp.Answer = []dns.RR{&dns.HINFO{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeHINFO, Class: dns.ClassINET, Ttl: anyTTL},
				Cpu: "RFC8482",
			}}
			break
		}
		k := keyOf(q)
		if e, ok := h.cache.get(k, h.now()); ok {
			fill(resp, q, e)
			break
		}
		return resp, &k
	default:
		resp.Rcode = dns.RcodeRefused
	}
	return resp, nil
}

// chaos answers the CH TXT names of the persona's name server. BIND adds
// the NS record of its built-in zone in the authority section.
func (h *Handler) chaos(resp *dns.Msg, q dns.Question) {
	var txt string
	switch name := strings.ToLower(q.Name); {
	case q.Qtype != dns.TypeTXT:
	case name == "version.bind." || name == "version.server.":
		txt = h.p.DNS.VersionBind
	case name == "hostname.bind." || name == "id.server.":
		if h.p.DNS.HostnameBind {
			txt = h.p.Hostname
		}
	}
	if txt == "" {
		resp.Rcode = dns.RcodeRefused
		return
	}
	resp.Authoritative = true
	resp.Answer = []dns.RR{&dns.TXT{
		Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeTXT, Class: dns.ClassCHAOS},
		Txt: []string{txt},
	}}
	if h.p.DNS.Software == "bind" {
		resp.Ns = []dns.RR{&dns.NS{
			Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeNS, Class: dns.ClassCHAOS},
			Ns:  strings.ToLower(q.Name),
		}}
	}
}

// resolve asks the upstream for the question of k and caches the reply.
func (h *Handler) resolve(q dns.Question, k cacheKey) (entry, error) {
	m := new(dns.Msg)
	m.SetQuestion(k.name, q.Qtype)
	m.Question[0].Qclass = q.Qclass
	m.RecursionDesired = true
	m.SetEdns0(udpEDNS, false)
	ctx, cancel := context.WithTimeout(context.Background(), resolveTime)
	defer cancel()
	a, err := h.up.Exchange(ctx, m)
	if err != nil {
		return entry{}, err
	}
	if a == nil {
		return entry{}, errors.New("dnspot: empty upstream reply")
	}
	e, ttl := entryOf(a)
	h.cache.put(k, e, ttl, h.now())
	return e, nil
}

// fill puts the records of e into resp. Answer records owned by the
// question name carry the name as the client wrote it.
func fill(resp *dns.Msg, q dns.Question, e entry) {
	resp.Rcode = e.rcode
	if resp.Rcode > 0xF {
		resp.Rcode = dns.RcodeServerFailure
	}
	for _, rr := range e.answer {
		if h := rr.Header(); strings.EqualFold(h.Name, q.Name) {
			h.Name = q.Name
		}
	}
	resp.Answer, resp.Ns = e.answer, e.ns
}
