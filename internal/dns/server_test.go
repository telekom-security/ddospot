package dnspot

import (
	"context"
	"errors"
	"math/rand"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/t3chn0m4g3/ddospot/internal/limit"
	"github.com/t3chn0m4g3/ddospot/internal/persona"
	"github.com/t3chn0m4g3/ddospot/internal/testutil"
)

var now = time.Date(2026, 10, 11, 9, 8, 7, 123456000, time.UTC)

func per(id string) *persona.Persona {
	for s := int64(0); ; s++ {
		p := persona.Roll(rand.New(rand.NewSource(s)))
		if p.ID == id {
			return &p
		}
	}
}

func newLim() *limit.Limiter {
	return limit.New(limit.Defaults(time.Minute), time.Now, testutil.NopObs{})
}

type fakeUp struct {
	healthy bool
	calls   atomic.Int32
	answer  func(q *dns.Msg) *dns.Msg
}

func (f *fakeUp) Healthy() bool { return f.healthy }
func (f *fakeUp) Exchange(_ context.Context, q *dns.Msg) (*dns.Msg, error) {
	f.calls.Add(1)
	return f.answer(q), nil
}

func txtAnswer(n int) func(*dns.Msg) *dns.Msg {
	return func(q *dns.Msg) *dns.Msg {
		m := new(dns.Msg)
		m.SetReply(q)
		for i := 0; i < n; i++ {
			m.Answer = append(m.Answer, &dns.TXT{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 300}, Txt: []string{strings.Repeat("a", 200)}})
		}
		return m
	}
}

func start(t *testing.T, h *Handler) (udp, tcp string) {
	pc, _ := net.ListenPacket("udp", "127.0.0.1:0")
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	su := &dns.Server{PacketConn: pc, Handler: h, MsgAcceptFunc: Accept, DecorateReader: StrictReader}
	st := &dns.Server{Listener: l, Handler: h, MsgAcceptFunc: Accept, DecorateReader: StrictReader}
	go su.ActivateAndServe()
	go st.ActivateAndServe()
	t.Cleanup(func() { su.Shutdown(); st.Shutdown() })
	time.Sleep(20 * time.Millisecond)
	return pc.LocalAddr().String(), l.Addr().String()
}

func TestVersionBind(t *testing.T) {
	p := per("centos7")
	udp, _ := start(t, NewHandler(p, newLim(), nil))
	m := new(dns.Msg)
	m.SetQuestion("version.bind.", dns.TypeTXT)
	m.Question[0].Qclass = dns.ClassCHAOS
	r, _, err := new(dns.Client).Exchange(m, udp)
	if err != nil || len(r.Answer) != 1 || r.Answer[0].(*dns.TXT).Txt[0] != p.DNS.VersionBind {
		t.Fatalf("%v %v", err, r)
	}
}

func TestRefusedWhenRecursionOff(t *testing.T) {
	udp, _ := start(t, NewHandler(per("debian11"), newLim(), nil))
	m := new(dns.Msg)
	m.SetQuestion("example.org.", dns.TypeA)
	r, _, _ := new(dns.Client).Exchange(m, udp)
	if r.Rcode != dns.RcodeRefused || r.RecursionAvailable {
		t.Fatalf("%v", r)
	}
}

func TestRefusedWhenUpstreamDown(t *testing.T) {
	up := &fakeUp{healthy: false, answer: txtAnswer(1)}
	udp, _ := start(t, NewHandler(per("debian11"), newLim(), up))
	m := new(dns.Msg)
	m.SetQuestion("example.org.", dns.TypeA)
	r, _, _ := new(dns.Client).Exchange(m, udp)
	if r.Rcode != dns.RcodeRefused || up.calls.Load() != 0 {
		t.Fatalf("%v calls=%d", r.Rcode, up.calls.Load())
	}
}

func TestUDPSizeAndTCP(t *testing.T) {
	up := &fakeUp{healthy: true, answer: txtAnswer(20)}
	udp, tcp := start(t, NewHandler(per("debian11"), newLim(), up))
	m := new(dns.Msg)
	m.SetQuestion("big.example.", dns.TypeTXT)
	r, _, _ := (&dns.Client{UDPSize: 512}).Exchange(m, udp)
	if !r.Truncated || len(r.Answer) != 0 {
		t.Fatalf("udp: tc=%v answers=%d", r.Truncated, len(r.Answer))
	}
	m.SetEdns0(4096, false)
	r, _, _ = new(dns.Client).Exchange(m, udp)
	if r.Len() > 1232 || !r.Truncated {
		t.Fatalf("edns: len=%d tc=%v", r.Len(), r.Truncated)
	}
	if b, err := r.Pack(); err != nil || len(b) > 1232 {
		t.Fatalf("edns: packed %d %v", len(b), err)
	}
	r, _, _ = (&dns.Client{Net: "tcp"}).Exchange(m, tcp)
	if r.Truncated || len(r.Answer) != 20 {
		t.Fatalf("tcp: %d", len(r.Answer))
	}
}

func TestBudgetIgnoresName(t *testing.T) {
	up := &fakeUp{healthy: true, answer: txtAnswer(1)}
	udp, _ := start(t, NewHandler(per("debian11"), newLim(), up))
	ok := 0
	for _, n := range []string{"a.example.", "A.example.", "b.example.", "B.EXAMPLE.", "c.example.", "d.example.", "e.example."} {
		m := new(dns.Msg)
		m.SetQuestion(n, dns.TypeA)
		if r, _, err := (&dns.Client{Timeout: 300 * time.Millisecond}).Exchange(m, udp); err == nil && r != nil {
			ok++
		}
	}
	if ok != 5 {
		t.Fatalf("answers %d, want 5", ok)
	}
}

func TestCacheIsCaseInsensitive(t *testing.T) {
	up := &fakeUp{healthy: true, answer: txtAnswer(1)}
	h := NewHandler(per("debian11"), limit.New(limit.Defaults(time.Minute), time.Now, testutil.NopObs{}), up)
	udp, _ := start(t, h)
	for _, n := range []string{"x.example.", "X.Example."} {
		m := new(dns.Msg)
		m.SetQuestion(n, dns.TypeA)
		new(dns.Client).Exchange(m, udp)
	}
	if up.calls.Load() != 1 {
		t.Fatalf("upstream calls %d", up.calls.Load())
	}
}

func TestAnyIsMinimal(t *testing.T) {
	up := &fakeUp{healthy: true, answer: txtAnswer(20)}
	udp, _ := start(t, NewHandler(per("debian11"), newLim(), up))
	m := new(dns.Msg)
	m.SetQuestion("example.org.", dns.TypeANY)
	r, _, _ := new(dns.Client).Exchange(m, udp)
	if len(r.Answer) != 1 || r.Answer[0].Header().Rrtype != dns.TypeHINFO || up.calls.Load() != 0 {
		t.Fatalf("%v", r)
	}
}

func FuzzServe(f *testing.F) {
	m := new(dns.Msg)
	m.SetQuestion("example.org.", dns.TypeA)
	b, _ := m.Pack()
	f.Add(b)
	f.Add([]byte{})
	h := NewHandler(per("centos6"), newLim(), &fakeUp{healthy: true, answer: txtAnswer(3)})
	f.Fuzz(func(t *testing.T, b []byte) {
		req := new(dns.Msg)
		if req.Unpack(b) != nil {
			return
		}
		w := &testutil.DNSRecorder{Remote: &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 5353}}
		h.ServeDNS(w, req)
		if w.Msg != nil && w.Msg.Len() > 1232 {
			t.Fatalf("udp answer %d bytes", w.Msg.Len())
		}
		if w.Msg != nil {
			if b, err := w.Msg.Pack(); err != nil || len(b) > 1232 {
				t.Fatalf("pack: %d %v", len(b), err)
			}
		}
		// The budget of the one source above is spent after a few inputs;
		// the answer is also built and sized without it.
		if resp, _ := h.build(req); resp != nil {
			b, err := Limit(resp, req, true).Pack()
			if err != nil || len(b) > maxSize(req, true) {
				t.Fatalf("built answer %d bytes, %v", len(b), err)
			}
		}
	})
}

// The tests below drive the handler directly through a recorder, each
// request from its own source unless the test says otherwise.

var srcN atomic.Uint32

func udpFrom() *testutil.DNSRecorder {
	n := srcN.Add(1)
	return &testutil.DNSRecorder{Remote: &net.UDPAddr{IP: net.IPv4(198, 51, byte(n>>8), byte(n)), Port: 40000}}
}

func tcpFrom() *testutil.DNSRecorder {
	n := srcN.Add(1)
	return &testutil.DNSRecorder{Remote: &net.TCPAddr{IP: net.IPv4(203, 0, byte(n>>8), byte(n)), Port: 40000}}
}

func query(name string, qtype, qclass uint16) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(name, qtype)
	m.Question[0].Qclass = qclass
	return m
}

func serve(t *testing.T, h *Handler, w *testutil.DNSRecorder, m *dns.Msg) *dns.Msg {
	t.Helper()
	h.ServeDNS(w, m)
	return w.Msg
}

func TestChaosNames(t *testing.T) {
	bind, masq := per("centos7"), per("debian11")
	cases := []struct {
		p     *persona.Persona
		name  string
		rcode int
		txt   string
	}{
		{bind, "version.bind.", dns.RcodeSuccess, bind.DNS.VersionBind},
		{bind, "VERSION.BIND.", dns.RcodeSuccess, bind.DNS.VersionBind},
		{bind, "version.server.", dns.RcodeSuccess, bind.DNS.VersionBind},
		{bind, "hostname.bind.", dns.RcodeSuccess, bind.Hostname},
		{bind, "id.server.", dns.RcodeSuccess, bind.Hostname},
		{bind, "authors.bind.", dns.RcodeRefused, ""},
		{masq, "version.bind.", dns.RcodeSuccess, masq.DNS.VersionBind},
		{masq, "hostname.bind.", dns.RcodeRefused, ""},
		{masq, "id.server.", dns.RcodeRefused, ""},
	}
	for _, c := range cases {
		h := NewHandler(c.p, newLim(), nil)
		r := serve(t, h, udpFrom(), query(c.name, dns.TypeTXT, dns.ClassCHAOS))
		if r == nil || r.Rcode != c.rcode {
			t.Fatalf("%s %s: %v", c.p.ID, c.name, r)
		}
		if c.txt == "" {
			if len(r.Answer) != 0 {
				t.Fatalf("%s %s: answers %v", c.p.ID, c.name, r.Answer)
			}
			continue
		}
		if len(r.Answer) != 1 {
			t.Fatalf("%s %s: answers %v", c.p.ID, c.name, r.Answer)
		}
		txt := r.Answer[0].(*dns.TXT)
		if txt.Txt[0] != c.txt || txt.Hdr.Class != dns.ClassCHAOS || txt.Hdr.Name != c.name || !r.Authoritative {
			t.Fatalf("%s %s: %v", c.p.ID, c.name, r)
		}
		// BIND adds the NS record of its built-in zone, dnsmasq does not.
		wantNS := 0
		if c.p.DNS.Software == "bind" {
			wantNS = 1
		}
		if len(r.Ns) != wantNS {
			t.Fatalf("%s %s: authority %v", c.p.ID, c.name, r.Ns)
		}
		if wantNS == 1 {
			ns := r.Ns[0].(*dns.NS)
			if ns.Hdr.Class != dns.ClassCHAOS || ns.Hdr.Name != c.name || ns.Ns != strings.ToLower(c.name) {
				t.Fatalf("%s %s: %v", c.p.ID, c.name, ns)
			}
		}
	}
}

func TestChaosOtherTypeRefused(t *testing.T) {
	h := NewHandler(per("centos7"), newLim(), nil)
	r := serve(t, h, udpFrom(), query("version.bind.", dns.TypeA, dns.ClassCHAOS))
	if r == nil || r.Rcode != dns.RcodeRefused || len(r.Answer) != 0 {
		t.Fatalf("%v", r)
	}
}

func TestOtherClassRefused(t *testing.T) {
	up := &fakeUp{healthy: true, answer: txtAnswer(1)}
	h := NewHandler(per("centos7"), newLim(), up)
	for _, cls := range []uint16{dns.ClassHESIOD, dns.ClassANY, 77} {
		r := serve(t, h, udpFrom(), query("example.org.", dns.TypeA, cls))
		if r == nil || r.Rcode != dns.RcodeRefused {
			t.Fatalf("class %d: %v", cls, r)
		}
	}
	if up.calls.Load() != 0 {
		t.Fatalf("upstream calls %d", up.calls.Load())
	}
}

func TestOpcodeAndQuestionCount(t *testing.T) {
	h := NewHandler(per("centos7"), newLim(), nil)
	m := query("example.org.", dns.TypeA, dns.ClassINET)
	m.Opcode = dns.OpcodeStatus
	r := serve(t, h, udpFrom(), m)
	if r == nil || r.Rcode != dns.RcodeNotImplemented || r.Opcode != dns.OpcodeStatus || r.Id != m.Id {
		t.Fatalf("opcode: %v", r)
	}
	m = query("example.org.", dns.TypeA, dns.ClassINET)
	m.Question = nil
	r = serve(t, h, udpFrom(), m)
	if r == nil || r.Rcode != dns.RcodeFormatError {
		t.Fatalf("no question: %v", r)
	}
	m = query("example.org.", dns.TypeA, dns.ClassINET)
	m.Question = append(m.Question, m.Question[0])
	r = serve(t, h, udpFrom(), m)
	if r == nil || r.Rcode != dns.RcodeFormatError || len(r.Question) != 0 {
		t.Fatalf("two questions: %v", r)
	}
}

func TestResponsesIgnored(t *testing.T) {
	h := NewHandler(per("centos7"), newLim(), nil)
	m := query("version.bind.", dns.TypeTXT, dns.ClassCHAOS)
	m.Response = true
	if r := serve(t, h, udpFrom(), m); r != nil {
		t.Fatalf("%v", r)
	}
	if Accept(dns.Header{Bits: 1 << 15, Qdcount: 1}) != dns.MsgIgnore {
		t.Fatal("accept response")
	}
	for _, dh := range []dns.Header{{Qdcount: 0}, {Qdcount: 2}, {Bits: 2 << 11, Qdcount: 1}, {Qdcount: 1, Ancount: 3, Arcount: 5}} {
		if Accept(dh) != dns.MsgAccept {
			t.Fatalf("accept %+v", dh)
		}
	}
}

func TestHeaderEcho(t *testing.T) {
	up := &fakeUp{healthy: true, answer: txtAnswer(1)}
	h := NewHandler(per("debian11"), newLim(), up)
	m := query("MiXeD.Example.", dns.TypeTXT, dns.ClassINET)
	m.CheckingDisabled = true
	r := serve(t, h, udpFrom(), m)
	if r == nil || !r.Response || r.Id != m.Id || !r.RecursionDesired || !r.RecursionAvailable || !r.CheckingDisabled {
		t.Fatalf("%v", r)
	}
	if len(r.Question) != 1 || r.Question[0] != m.Question[0] {
		t.Fatalf("question %v", r.Question)
	}
	if len(r.Answer) != 1 || r.Answer[0].Header().Name != "MiXeD.Example." {
		t.Fatalf("answer %v", r.Answer)
	}
	m.RecursionDesired = false
	m.Id++
	r = serve(t, h, udpFrom(), m)
	if r == nil || r.RecursionDesired || r.Id != m.Id || len(r.Answer) != 1 {
		t.Fatalf("cached: %v", r)
	}
}

func TestUpstreamQuery(t *testing.T) {
	var got *dns.Msg
	up := &fakeUp{healthy: true, answer: func(q *dns.Msg) *dns.Msg { got = q.Copy(); return txtAnswer(1)(q) }}
	h := NewHandler(per("debian11"), newLim(), up)
	m := query("Sub.Example.ORG.", dns.TypeAAAA, dns.ClassINET)
	m.RecursionDesired = false
	m.SetEdns0(4096, true)
	serve(t, h, udpFrom(), m)
	if got == nil || !got.RecursionDesired || got.Question[0].Name != "sub.example.org." || got.Question[0].Qtype != dns.TypeAAAA {
		t.Fatalf("%v", got)
	}
	o := got.IsEdns0()
	if o == nil || o.UDPSize() != 1232 || o.Do() {
		t.Fatalf("opt %v", o)
	}
}

func TestMinimalAnswer(t *testing.T) {
	up := &fakeUp{healthy: true, answer: func(q *dns.Msg) *dns.Msg {
		m := txtAnswer(1)(q)
		m.Ns = []dns.RR{&dns.NS{Hdr: dns.RR_Header{Name: "example.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 300}, Ns: "ns.example."}}
		m.Extra = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: "ns.example.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: net.IPv4(192, 0, 2, 53)}}
		m.SetEdns0(1232, false)
		return m
	}}
	h := NewHandler(per("debian11"), newLim(), up)
	r := serve(t, h, udpFrom(), query("x.example.", dns.TypeTXT, dns.ClassINET))
	if r == nil || len(r.Answer) != 1 || len(r.Ns) != 0 || len(r.Extra) != 0 {
		t.Fatalf("%v", r)
	}
	m := query("x.example.", dns.TypeTXT, dns.ClassINET)
	m.SetEdns0(4096, false)
	r = serve(t, h, udpFrom(), m)
	if r == nil || len(r.Ns) != 0 || len(r.Extra) != 1 || r.IsEdns0() == nil {
		t.Fatalf("edns: %v", r)
	}
}

func TestOPTSizeFromPersona(t *testing.T) {
	for _, id := range []string{"centos6", "debian11"} {
		p := per(id)
		h := NewHandler(p, newLim(), nil)
		m := query("version.bind.", dns.TypeTXT, dns.ClassCHAOS)
		m.SetEdns0(1400, true)
		r := serve(t, h, udpFrom(), m)
		o := r.IsEdns0()
		if o == nil || o.UDPSize() != p.DNS.EDNSSize || o.Do() {
			t.Fatalf("%s: %v", id, o)
		}
		r = serve(t, h, udpFrom(), query("version.bind.", dns.TypeTXT, dns.ClassCHAOS))
		if r.IsEdns0() != nil {
			t.Fatalf("%s: OPT without one in the request", id)
		}
	}
}

func TestRcodeFromUpstream(t *testing.T) {
	up := &fakeUp{healthy: true, answer: func(q *dns.Msg) *dns.Msg {
		m := new(dns.Msg)
		m.SetRcode(q, dns.RcodeNameError)
		m.Ns = []dns.RR{&dns.SOA{Hdr: dns.RR_Header{Name: "example.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 3600}, Ns: "ns.example.", Mbox: "h.example.", Minttl: 300}}
		return m
	}}
	h := NewHandler(per("debian11"), newLim(), up)
	for i := 0; i < 2; i++ {
		r := serve(t, h, udpFrom(), query("nx.example.", dns.TypeA, dns.ClassINET))
		if r == nil || r.Rcode != dns.RcodeNameError || len(r.Answer) != 0 || len(r.Ns) != 1 {
			t.Fatalf("%v", r)
		}
		if soa := r.Ns[0].(*dns.SOA); soa.Hdr.Ttl > 300 || soa.Hdr.Ttl < 299 {
			t.Fatalf("soa ttl %d", soa.Hdr.Ttl)
		}
	}
	if up.calls.Load() != 1 {
		t.Fatalf("upstream calls %d", up.calls.Load())
	}
}

type errUp struct{ calls atomic.Int32 }

func (*errUp) Healthy() bool { return true }
func (e *errUp) Exchange(context.Context, *dns.Msg) (*dns.Msg, error) {
	e.calls.Add(1)
	return nil, errors.New("no answer")
}

func TestUpstreamErrorNoAnswer(t *testing.T) {
	up := &errUp{}
	h := NewHandler(per("debian11"), newLim(), up)
	if r := serve(t, h, udpFrom(), query("x.example.", dns.TypeA, dns.ClassINET)); r != nil {
		t.Fatalf("%v", r)
	}
	if up.calls.Load() != 1 {
		t.Fatalf("upstream calls %d", up.calls.Load())
	}
}

func TestRefusedSourceSkipsUpstream(t *testing.T) {
	up := &fakeUp{healthy: true, answer: txtAnswer(1)}
	h := NewHandler(per("debian11"), newLim(), up)
	w := udpFrom()
	for i := 0; i < 8; i++ {
		w.Msg = nil
		serve(t, h, w, query("n"+string(rune('a'+i))+".example.", dns.TypeA, dns.ClassINET))
	}
	if up.calls.Load() != 5 {
		t.Fatalf("upstream calls %d", up.calls.Load())
	}
}

func TestTCPOutsideGlobalBytes(t *testing.T) {
	cfg := limit.Defaults(time.Minute)
	cfg.GlobalBPS = 600
	lim := limit.New(cfg, time.Now, testutil.NopObs{})
	up := &fakeUp{healthy: true, answer: txtAnswer(20)}
	h := NewHandler(per("debian11"), lim, up)
	r := serve(t, h, tcpFrom(), query("big.example.", dns.TypeTXT, dns.ClassINET))
	if r == nil || len(r.Answer) != 20 {
		t.Fatalf("tcp: %v", r)
	}
	m := query("big2.example.", dns.TypeTXT, dns.ClassINET)
	m.SetEdns0(1232, false)
	if r := serve(t, h, udpFrom(), m); r != nil {
		t.Fatalf("udp over the byte budget: %d bytes", r.Len())
	}
}

func TestAnyRecord(t *testing.T) {
	h := NewHandler(per("debian11"), newLim(), &fakeUp{healthy: true, answer: txtAnswer(1)})
	r := serve(t, h, udpFrom(), query("Example.org.", dns.TypeANY, dns.ClassINET))
	hi, ok := r.Answer[0].(*dns.HINFO)
	if !ok || hi.Cpu != "RFC8482" || hi.Os != "" || hi.Hdr.Ttl != 3789 || hi.Hdr.Name != "Example.org." || !r.RecursionAvailable {
		t.Fatalf("%v", r)
	}
}

func TestFields(t *testing.T) {
	cases := []struct {
		q         dns.Question
		name, typ string
		cls       string
	}{
		{dns.Question{Name: "Example.org.", Qtype: dns.TypeA, Qclass: dns.ClassINET}, "Example.org.", "A", "IN"},
		{dns.Question{Name: "version.bind.", Qtype: dns.TypeTXT, Qclass: dns.ClassCHAOS}, "version.bind.", "TXT", "CH"},
		{dns.Question{Name: "a\\000b.", Qtype: 65000, Qclass: 77}, "a\\000b.", "TYPE65000", "CLASS77"},
	}
	for _, c := range cases {
		m := new(dns.Msg)
		m.Id = 7
		m.Question = []dns.Question{c.q}
		f := fields(m)
		if f["dns_name"] != c.name || f["dns_type"] != c.typ || f["dns_cls"] != c.cls || f["opcode"] != 0 {
			t.Fatalf("%v", f)
		}
	}
	m := new(dns.Msg)
	m.Opcode = dns.OpcodeUpdate
	if f := fields(m); f["opcode"] != dns.OpcodeUpdate {
		t.Fatalf("%v", f)
	}
}

func TestStrictReaderDropsBrokenBody(t *testing.T) {
	udp, _ := start(t, NewHandler(per("centos7"), newLim(), nil))
	c, err := net.Dial("udp", udp)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	m := query("version.bind.", dns.TypeTXT, dns.ClassCHAOS)
	b, _ := m.Pack()
	// The header is whole, the question name points past the end.
	broken := append(append([]byte{}, b[:12]...), 0xc0, 0xff, 0, 16, 0, 3)
	if new(dns.Msg).Unpack(broken) == nil {
		t.Fatal("test message parses")
	}
	c.Write(broken)
	c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if n, err := c.Read(make([]byte, 512)); err == nil {
		t.Fatalf("answer of %d bytes", n)
	}
	c.Write(b)
	c.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 512)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	r := new(dns.Msg)
	if err := r.Unpack(buf[:n]); err != nil || len(r.Answer) != 1 {
		t.Fatalf("%v %v", err, r)
	}
}

func TestNotImplementedWithinBudget(t *testing.T) {
	udp, _ := start(t, NewHandler(per("centos7"), newLim(), nil))
	got := 0
	for i := 0; i < 7; i++ {
		m := query("example.org.", dns.TypeA, dns.ClassINET)
		m.Opcode = dns.OpcodeUpdate
		r, _, err := (&dns.Client{Timeout: 300 * time.Millisecond}).Exchange(m, udp)
		if err == nil {
			if r.Rcode != dns.RcodeNotImplemented {
				t.Fatalf("%v", r)
			}
			got++
		}
	}
	if got != 5 {
		t.Fatalf("answers %d, want 5", got)
	}
}

func TestLargeAnswerNotCached(t *testing.T) {
	up := &fakeUp{healthy: true, answer: txtAnswer(20)}
	h := NewHandler(per("debian11"), newLim(), up)
	for i := 0; i < 2; i++ {
		if r := serve(t, h, tcpFrom(), query("big.example.", dns.TypeTXT, dns.ClassINET)); r == nil || len(r.Answer) != 20 {
			t.Fatalf("%v", r)
		}
	}
	if up.calls.Load() != 2 {
		t.Fatalf("upstream calls %d", up.calls.Load())
	}
	up.answer = txtAnswer(10)
	for i := 0; i < 2; i++ {
		serve(t, h, tcpFrom(), query("mid.example.", dns.TypeTXT, dns.ClassINET))
	}
	if up.calls.Load() != 3 {
		t.Fatalf("upstream calls %d", up.calls.Load())
	}
}

func TestCNAMEToNoData(t *testing.T) {
	up := &fakeUp{healthy: true, answer: func(q *dns.Msg) *dns.Msg {
		m := new(dns.Msg)
		m.SetReply(q)
		m.Answer = []dns.RR{&dns.CNAME{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 3600}, Target: "y.example."}}
		m.Ns = []dns.RR{soaRR(86400, 86400)}
		return m
	}}
	h := NewHandler(per("debian11"), newLim(), up)
	t0 := time.Now()
	h.now = func() time.Time { return t0 }
	serve(t, h, udpFrom(), query("x.example.", dns.TypeAAAA, dns.ClassINET))
	h.now = func() time.Time { return t0.Add(899 * time.Second) }
	r := serve(t, h, udpFrom(), query("x.example.", dns.TypeAAAA, dns.ClassINET))
	if r == nil || len(r.Answer) != 1 || len(r.Ns) != 1 || r.Ns[0].Header().Ttl != 1 || up.calls.Load() != 1 {
		t.Fatalf("calls %d: %v", up.calls.Load(), r)
	}
	h.now = func() time.Time { return t0.Add(900 * time.Second) }
	serve(t, h, udpFrom(), query("x.example.", dns.TypeAAAA, dns.ClassINET))
	if up.calls.Load() != 2 {
		t.Fatalf("upstream calls %d after 900 s", up.calls.Load())
	}
}

type targetCount struct {
	testutil.NopObs
	n atomic.Int32
}

func (o *targetCount) TargetStart(limit.Source) { o.n.Add(1) }

func TestTCPSourceAnsweredFiveTimesNoTarget(t *testing.T) {
	obs := &targetCount{}
	h := NewHandler(per("centos7"), limit.New(limit.Defaults(time.Minute), time.Now, obs), nil)
	src := &net.TCPAddr{IP: net.IPv4(203, 0, 113, 77), Port: 40000}
	got := 0
	for i := 0; i < 8; i++ {
		if serve(t, h, &testutil.DNSRecorder{Remote: src}, query("version.bind.", dns.TypeTXT, dns.ClassCHAOS)) != nil {
			got++
		}
	}
	if got != 5 || obs.n.Load() != 0 {
		t.Fatalf("answers %d, target_start %d", got, obs.n.Load())
	}
	udp := &net.UDPAddr{IP: src.IP, Port: 40000}
	if serve(t, h, &testutil.DNSRecorder{Remote: udp}, query("version.bind.", dns.TypeTXT, dns.ClassCHAOS)) == nil {
		t.Fatal("TCP queries counted for the UDP budget")
	}
}
