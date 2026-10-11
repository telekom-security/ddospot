// Package ssdp implements the SSDP service on UDP port 1900: M-SEARCH
// requests are answered as the UPnP daemon of the persona (MiniUPnPd or
// MiniDLNA) answers them.
package ssdp

import (
	"fmt"
	"math/rand"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/t3chn0m4g3/ddospot/internal/limit"
	"github.com/t3chn0m4g3/ddospot/internal/persona"
	"github.com/t3chn0m4g3/ddospot/internal/udp"
)

// Port is the well-known port of the service.
const Port = 1900

const (
	// maxDatagrams is the most datagrams sent for one request.
	maxDatagrams = 8

	rootDevice = "upnp:rootdevice"
	searchAll  = "ssdp:all"

	// miniupnpd 2.2.1 configure: SSDP_PACKET_MAX_LEN 1024; SendSSDPResponse
	// sends at most sizeof(buf) - 1 bytes.
	upnpdMaxLen = 1024 - 1

	// miniupnpd 2.2.1 minissdp.c ProcessSSDPData: "Non-zero default
	// delay". Debian builds without --strict, so DELAY_MSEARCH_RESPONSE
	// is off and MX is not read: every answer leaves after 50 ms.
	upnpdDelay = 50 * time.Millisecond

	// minidlna.conf of minidlna 1.1.5, 1.2.1 and 1.3.0: notify_interval=900;
	// SendSSDPResponse: CACHE-CONTROL max-age=(notify_interval<<1)+10.
	dlnaMaxAge = 900<<1 + 10

	// minidlna SendSSDPResponse: strftime "%a, %d %b %Y %H:%M:%S GMT".
	httpDate = "Mon, 02 Jan 2006 15:04:05 GMT"
)

// upnpdOrder is known_service_types of miniupnpd 2.2.1 minissdp.c as
// Debian builds it (configure --igd2 --ipv6: IGD_V2, ENABLE_6FC_SERVICE,
// ADVERTISE_WANPPPCONN, ENABLE_L3F_SERVICE). It is the order of the
// answers to ssdp:all and of the search for a single target.
var upnpdOrder = []string{
	rootDevice,
	"urn:schemas-upnp-org:device:InternetGatewayDevice:",
	"urn:schemas-upnp-org:device:WANConnectionDevice:",
	"urn:schemas-upnp-org:device:WANDevice:",
	"urn:schemas-upnp-org:service:WANIPConnection:",
	"urn:schemas-upnp-org:service:DeviceProtection:",
	"urn:schemas-upnp-org:service:WANIPv6FirewallControl:",
	"urn:schemas-upnp-org:service:WANCommonInterfaceConfig:",
	"urn:schemas-upnp-org:service:WANPPPConnection:",
	"urn:schemas-upnp-org:service:Layer3Forwarding:",
}

// target is one search target of a device: the uuid, upnp:rootdevice or
// a device or service type.
type target struct {
	st      string // as announced, with version
	prefix  string // type without version (ending in ':'), else st
	version string // digits after the last ':' of a type, else ""
	uuid    string // "uuid:..." of the device
}

func typeTarget(urn, uuid string) target {
	prefix, version := urn, ""
	if i := strings.LastIndexByte(urn, ':'); i >= 0 && i < len(urn)-1 {
		if _, err := strconv.Atoi(urn[i+1:]); err == nil {
			prefix, version = urn[:i+1], urn[i+1:]
		}
	}
	return target{st: urn, prefix: prefix, version: version, uuid: uuid}
}

func uuidOf(p *persona.Persona, i int) string {
	if i < len(p.UUIDs) {
		return "uuid:" + p.UUIDs[i]
	}
	return "uuid:" + p.UUIDs[0]
}

// Answer builds the datagrams for one request, nil = no matching target.
// Pure function, no I/O; now is the time of the DATE header.
func Answer(p *persona.Persona, r Request, now time.Time) [][]byte {
	if len(p.UUIDs) == 0 || len(p.SSDP.Devices) == 0 {
		return nil
	}
	var out [][]byte
	if p.SSDP.Kind == "minidlna" {
		out = dlnaAnswer(p, r, now)
	} else {
		out = upnpdAnswer(p, r)
	}
	if len(out) > maxDatagrams {
		out = out[:maxDatagrams]
	}
	return out
}

func location(p *persona.Persona) string {
	return fmt.Sprintf("http://%s:%d%s", p.LAN, p.SSDPPort, p.SSDP.Path)
}

// upnpdTypes returns upnp:rootdevice and the device and service types of
// the persona in the order of known_service_types; types missing there
// follow in the order of the persona.
func upnpdTypes(p *persona.Persona) []target {
	rank := func(prefix string) int {
		for i, s := range upnpdOrder {
			if s == prefix {
				return i
			}
		}
		return len(upnpdOrder)
	}
	ts := []target{{st: rootDevice, prefix: rootDevice, uuid: uuidOf(p, 0)}}
	for i, d := range p.SSDP.Devices {
		ts = append(ts, typeTarget(d.Type, uuidOf(p, i)))
		for _, s := range d.Services {
			ts = append(ts, typeTarget(s, uuidOf(p, i)))
		}
	}
	sorted := make([]target, 0, len(ts))
	for r := 0; r <= len(upnpdOrder); r++ {
		for _, t := range ts {
			if rank(t.prefix) == r {
				sorted = append(sorted, t)
			}
		}
	}
	return sorted
}

// upnpdAnswer follows ProcessSSDPData of miniupnpd 2.2.1 minissdp.c
// without UPNP_STRICT: the first type that is a prefix of ST answers with
// the ST of the request (SSDP_RESPOND_SAME_VERSION), ssdp:all answers
// every type and then every uuid, a uuid answers only itself.
func upnpdAnswer(p *persona.Persona, r Request) [][]byte {
	var out [][]byte
	types := upnpdTypes(p)
	for _, t := range types {
		if strings.HasPrefix(r.ST, t.prefix) {
			out = append(out, upnpdDatagram(p, r.ST, t.uuid))
			break
		}
	}
	if r.ST == searchAll {
		for _, t := range types {
			out = append(out, upnpdDatagram(p, t.st, t.uuid))
		}
		for i := range p.SSDP.Devices {
			u := uuidOf(p, i)
			out = append(out, upnpdDatagram(p, u, u))
		}
	}
	for i := range p.SSDP.Devices {
		if u := uuidOf(p, i); r.ST == u {
			out = append(out, upnpdDatagram(p, u, u))
			break
		}
	}
	return out
}

// upnpdDatagram is SendSSDPResponse of miniupnpd 2.2.1 minissdp.c as
// Debian builds it (no ENABLE_HTTP_DATE, ENABLE_HTTPS or RANDOMIZE_URLS).
// USN is the uuid alone when ST is that uuid, else uuid::ST.
func upnpdDatagram(p *persona.Persona, st, uuid string) []byte {
	usn := uuid
	if st != uuid {
		usn = uuid + "::" + st
	}
	b := []byte("HTTP/1.1 200 OK\r\n" +
		"CACHE-CONTROL: max-age=120\r\n" +
		"ST: " + st + "\r\n" +
		"USN: " + usn + "\r\n" +
		"EXT:\r\n" +
		"SERVER: " + p.SSDP.Server + "\r\n" +
		"LOCATION: " + location(p) + "\r\n" +
		"OPT: \"http://schemas.upnp.org/upnp/1/0/\"; ns=01\r\n" +
		fmt.Sprintf("01-NLS: %d\r\n", p.BootID) +
		fmt.Sprintf("BOOTID.UPNP.ORG: %d\r\n", p.BootID) +
		fmt.Sprintf("CONFIGID.UPNP.ORG: %d\r\n", p.ConfigID) +
		"\r\n")
	if len(b) > upnpdMaxLen {
		b = b[:upnpdMaxLen]
	}
	return b
}

// dlnaTargets is known_service_types of minidlna minissdp.c (the same in
// 1.1.5, 1.2.1 and 1.3.0): the uuid, upnp:rootdevice, then the device and
// service types.
func dlnaTargets(p *persona.Persona) []target {
	u := uuidOf(p, 0)
	ts := []target{{st: u, prefix: u, uuid: u}, {st: rootDevice, prefix: rootDevice, uuid: u}}
	for _, d := range p.SSDP.Devices {
		ts = append(ts, typeTarget(d.Type, u))
		for _, s := range d.Services {
			ts = append(ts, typeTarget(s, u))
		}
	}
	return ts
}

// dlnaAnswer follows ProcessSSDPRequest of minidlna minissdp.c: a request
// without a valid MX gets no answer; the first target that is a prefix of
// ST answers when the rest of ST is empty, or the version followed by
// blanks; ssdp:all answers every target.
func dlnaAnswer(p *persona.Persona, r Request, now time.Time) [][]byte {
	if !r.HasMX {
		return nil
	}
	ts := dlnaTargets(p)
	date := now.UTC().Format(httpDate)
	for i, t := range ts {
		l := len(t.prefix)
		if l > len(r.ST) || r.ST[:l] != t.prefix {
			continue
		}
		if l != len(r.ST) {
			if t.version != "" && strings.HasPrefix(r.ST[l:], t.version) {
				l += len(t.version)
			}
			for l < len(r.ST) && isSpace(r.ST[l]) {
				l++
			}
			if l != len(r.ST) {
				return nil
			}
		}
		return [][]byte{dlnaDatagram(p, ts, i, date)}
	}
	if r.ST == searchAll {
		out := make([][]byte, 0, len(ts))
		for i := range ts {
			out = append(out, dlnaDatagram(p, ts, i, date))
		}
		return out
	}
	return nil
}

func isSpace(c byte) bool {
	return c == ' ' || c >= '\t' && c <= '\r'
}

// dlnaDatagram is SendSSDPResponse of minidlna minissdp.c (the same in
// 1.1.5, 1.2.1 and 1.3.0): ST is the target as announced, USN the uuid
// for target 0 and uuid::ST for the others.
func dlnaDatagram(p *persona.Persona, ts []target, i int, date string) []byte {
	t := ts[i]
	usn := t.uuid
	if i > 0 {
		usn += "::" + t.st
	}
	return []byte("HTTP/1.1 200 OK\r\n" +
		"CACHE-CONTROL: max-age=" + strconv.Itoa(dlnaMaxAge) + "\r\n" +
		"DATE: " + date + "\r\n" +
		"ST: " + t.st + "\r\n" +
		"USN: " + usn + "\r\n" +
		"EXT:\r\n" +
		"SERVER: " + p.SSDP.Server + "\r\n" +
		"LOCATION: " + location(p) + "\r\n" +
		"Content-Length: 0\r\n" +
		"\r\n")
}

// delay returns the wait before the answer to r, as the daemon of p
// waits. Neither daemon reads MX for it:
//   - miniupnpd 2.2.1 (Debian, no DELAY_MSEARCH_RESPONSE): 50 ms;
//   - minidlna 1.1.5 and 1.2.1: _usleep(random()>>20) before a single
//     answer (0-2047 µs), none before the answers to ssdp:all;
//   - minidlna 1.3.0: _usleep(13000, 20000) before a single answer,
//     _usleep(13000, 30000) once before the answers to ssdp:all.
func delay(p *persona.Persona, r Request, rng *rand.Rand) time.Duration {
	us := func(lo, hi int64) time.Duration {
		return time.Duration(lo+rng.Int63n(hi-lo+1)) * time.Microsecond
	}
	if p.SSDP.Kind != "minidlna" {
		return upnpdDelay
	}
	all := r.ST == searchAll
	if dlnaNewDelay(p.SSDP.Server) {
		if all {
			return us(13000, 30000)
		}
		return us(13000, 20000)
	}
	if all {
		return 0
	}
	return us(0, 2047)
}

// dlnaNewDelay reports whether the SERVER string names minidlna 1.3 or
// later, whose waits are longer than those of 1.2.
func dlnaNewDelay(server string) bool {
	i := strings.LastIndex(server, "MiniDLNA/")
	if i < 0 {
		return true
	}
	parts := strings.SplitN(server[i+len("MiniDLNA/"):], ".", 3)
	if len(parts) < 2 {
		return true
	}
	major, err1 := strconv.Atoi(parts[0])
	minor, err2 := strconv.Atoi(parts[1])
	if err1 != nil || err2 != nil {
		return true
	}
	return major > 1 || major == 1 && minor >= 3
}

// Server answers M-SEARCH requests within the budgets of its limiter.
type Server struct {
	conn *net.UDPConn
	lim  *limit.Limiter
	p    *persona.Persona

	mu     sync.Mutex // guards rng, timers and closed
	rng    *rand.Rand
	timers map[*time.Timer]struct{}
	closed bool
	wg     sync.WaitGroup // pending and running answers
}

// New returns a Server reading from conn that answers as persona p.
func New(conn *net.UDPConn, lim *limit.Limiter, p *persona.Persona) *Server {
	return &Server{
		conn:   conn,
		lim:    lim,
		p:      p,
		rng:    rand.New(rand.NewSource(time.Now().UnixNano())),
		timers: map[*time.Timer]struct{}{},
	}
}

// Serve answers datagrams until the connection is closed.
func (s *Server) Serve() error {
	return udp.Loop(s.conn, s.handle)
}

// Close stops the answers that wait for their delay; they are not sent.
// It returns once no answer is being sent.
func (s *Server) Close() {
	s.mu.Lock()
	if !s.closed {
		s.closed = true
		for t := range s.timers {
			if t.Stop() {
				s.wg.Done()
			}
		}
		s.timers = nil
	}
	s.mu.Unlock()
	s.wg.Wait()
}

func (s *Server) handle(req []byte, src netip.AddrPort) {
	// minidlna listens on IPv4 only; the personas have no IPv6 address
	// for the LOCATION of a miniupnpd answer.
	if !src.Addr().Unmap().Is4() {
		return
	}
	r, ok := Parse(req)
	if !ok {
		return
	}
	resp := Answer(s.p, r, time.Now())
	if resp == nil {
		return
	}
	sum := 0
	for _, d := range resp {
		sum += len(d)
	}
	sample := limit.Sample{Transport: "udp", Req: req, RespSize: sum, Fields: map[string]any{"st": r.ST, "mx": r.MXRaw}}
	if !s.lim.Admit(limit.SSDP, src, sample, len(resp), sum) {
		return
	}
	s.schedule(r, resp, src)
}

// schedule sends resp to dst after the delay of the daemon.
func (s *Server) schedule(r Request, resp [][]byte, dst netip.AddrPort) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	var t *time.Timer
	s.wg.Add(1)
	t = time.AfterFunc(delay(s.p, r, s.rng), func() {
		defer s.wg.Done()
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			return
		}
		delete(s.timers, t)
		s.mu.Unlock()
		for _, d := range resp {
			s.conn.WriteToUDPAddrPort(d, dst)
		}
	})
	s.timers[t] = struct{}{}
}
