package limit

import (
	"fmt"
	"net/netip"
	"sync"
	"testing"
	"time"
)

type clock struct{ t time.Time }
type rec struct {
	scanner, tstart, tend []Source
	nstart, nend          []Net
}

func (r *rec) Scanner(s Source)     { r.scanner = append(r.scanner, s) }
func (r *rec) TargetStart(s Source) { r.tstart = append(r.tstart, s) }
func (r *rec) TargetEnd(s Source)   { r.tend = append(r.tend, s) }
func (r *rec) NetStart(n Net)       { r.nstart = append(r.nstart, n) }
func (r *rec) NetEnd(n Net)         { r.nend = append(r.nend, n) }

func newTest(maxEntries int) (*Limiter, *clock, *rec) {
	c := &clock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	r := &rec{}
	cfg := Defaults(60 * time.Second)
	cfg.MaxSources, cfg.MaxNets = maxEntries, maxEntries
	return New(cfg, func() time.Time { return c.t }, r), c, r
}

func ap(s string) netip.AddrPort { return netip.MustParseAddrPort(s) }

func TestResponseBudgetPerSource(t *testing.T) {
	l, c, r := newTest(100)
	for i := 0; i < 5; i++ {
		if !l.Admit(NTP, ap("198.51.100.7:4000"), Sample{}, 1, 48) {
			t.Fatalf("answer %d refused", i+1)
		}
		c.t = c.t.Add(time.Second)
	}
	if l.Admit(NTP, ap("198.51.100.7:4000"), Sample{}, 1, 48) {
		t.Fatal("6th answer allowed")
	}
	if len(r.tstart) != 1 {
		t.Fatalf("target_start events = %d, want 1", len(r.tstart))
	}
	if !l.Admit(DNS, ap("198.51.100.7:4000"), Sample{}, 1, 60) {
		t.Fatal("other protocol shares the source budget")
	}
}

func TestBlockLastsUntilQuiet(t *testing.T) {
	l, c, r := newTest(100)
	for i := 0; i < 6; i++ {
		l.Admit(SSDP, ap("198.51.100.7:1"), Sample{}, 1, 100)
	}
	for i := 0; i < 30; i++ { // a packet every 5 min keeps the block
		c.t = c.t.Add(5 * time.Minute)
		l.Tick()
		if l.Admit(SSDP, ap("198.51.100.7:1"), Sample{}, 1, 100) {
			t.Fatalf("answered after %d min", (i+1)*5)
		}
	}
	c.t = c.t.Add(10*time.Minute + time.Second)
	l.Tick()
	if len(r.tend) != 1 {
		t.Fatalf("target_end events = %d, want 1", len(r.tend))
	}
	if !l.Admit(SSDP, ap("198.51.100.7:1"), Sample{}, 1, 100) {
		t.Fatal("no answer after 10 min quiet")
	}
}

func TestNetBudgetAcrossProtocols(t *testing.T) {
	l, _, r := newTest(1000)
	protos := []Proto{Chargen, DNS, NTP, SSDP}
	ok := 0
	for i := 0; i < 40; i++ {
		src := netip.AddrPortFrom(netip.AddrFrom4([4]byte{203, 0, 113, byte(i)}), 1000)
		if l.Admit(protos[i%4], src, Sample{}, 1, 64) {
			ok++
		}
	}
	if ok != 20 {
		t.Fatalf("answers to one /24 = %d, want 20", ok)
	}
	if len(r.nstart) != 1 || r.nstart[0].Prefix.String() != "203.0.113.0/24" {
		t.Fatalf("net_start = %+v", r.nstart)
	}
}

func TestNoSourceEventsInsideBlockedNet(t *testing.T) {
	l, c, r := newTest(1000)
	for round := 0; round < 3; round++ {
		for i := 0; i < 30; i++ {
			l.Admit(Chargen, netip.AddrPortFrom(netip.AddrFrom4([4]byte{203, 0, 113, byte(i)}), 1), Sample{}, 1, 1024)
		}
	}
	c.t = c.t.Add(61 * time.Second)
	l.Tick()
	c.t = c.t.Add(11 * time.Minute)
	l.Tick()
	if len(r.tstart) != 0 || len(r.tend) != 0 {
		t.Fatalf("per-source target events inside a blocked net: %d/%d", len(r.tstart), len(r.tend))
	}
	if len(r.nend) != 1 || r.nend[0].Sources != 30 {
		t.Fatalf("net_end = %+v", r.nend)
	}
	if len(r.scanner) != 0 {
		t.Fatalf("scanner events inside a blocked net = %d, want 0", len(r.scanner))
	}
}

func TestScannerAfterHold(t *testing.T) {
	l, c, r := newTest(100)
	s := Sample{Transport: "udp", Req: []byte{0x1b}, Fields: map[string]any{"mode": "DATA"}}
	l.Admit(NTP, ap("192.0.2.10:123"), s, 1, 48)
	c.t = c.t.Add(59 * time.Second)
	l.Tick()
	if len(r.scanner) != 0 {
		t.Fatal("scanner reported before the hold")
	}
	c.t = c.t.Add(2 * time.Second)
	l.Tick()
	if len(r.scanner) != 1 || r.scanner[0].Packets != 1 || r.scanner[0].Sample.Fields["mode"] != "DATA" {
		t.Fatalf("scanner = %+v", r.scanner)
	}
}

func TestTargetBeforeHoldIsNoScanner(t *testing.T) {
	l, c, r := newTest(100)
	for i := 0; i < 8; i++ {
		l.Admit(DNS, ap("192.0.2.20:53"), Sample{}, 1, 100)
	}
	c.t = c.t.Add(61 * time.Second)
	l.Tick()
	if len(r.scanner) != 0 || len(r.tstart) != 1 {
		t.Fatalf("scanner=%d target_start=%d", len(r.scanner), len(r.tstart))
	}
}

func TestGlobalBudget(t *testing.T) {
	l, _, _ := newTest(100000)
	ok := 0
	for i := 0; i < 200; i++ {
		src := netip.AddrPortFrom(netip.AddrFrom4([4]byte{10, byte(i), 0, 1}), 1)
		if l.Admit(Chargen, src, Sample{}, 1, 1024) {
			ok++
		}
	}
	if ok != 50 {
		t.Fatalf("answers in one instant = %d, want 50 (packet budget)", ok)
	}
}

func TestZeroSizeSkipsGlobalBudget(t *testing.T) {
	l, _, _ := newTest(100000)
	for i := 0; i < 50; i++ {
		src := netip.AddrPortFrom(netip.AddrFrom4([4]byte{10, byte(i), 0, 1}), 1)
		if !l.Admit(Chargen, src, Sample{}, 1, 1024) {
			t.Fatalf("answer %d refused", i+1)
		}
	}
	if l.Admit(Chargen, ap("10.200.0.1:1"), Sample{}, 1, 1024) {
		t.Fatal("global budget not exhausted")
	}
	if !l.Admit(DNS, ap("10.201.0.1:1"), Sample{Transport: "tcp"}, 0, 0) {
		t.Fatal("zero-size admit refused by the global budget")
	}
}

func TestFailClosedWhenFull(t *testing.T) {
	l, _, _ := newTest(2)
	l.Admit(NTP, ap("192.0.2.1:1"), Sample{}, 1, 48)
	l.Admit(NTP, ap("192.0.2.2:1"), Sample{}, 1, 48)
	if l.Admit(NTP, ap("192.0.2.3:1"), Sample{}, 1, 48) {
		t.Fatal("answered with a full table")
	}
	if !l.Admit(NTP, ap("192.0.2.1:1"), Sample{}, 1, 48) {
		t.Fatal("known source refused")
	}
}

func TestFlush(t *testing.T) {
	l, _, r := newTest(1000)
	l.Admit(NTP, ap("192.0.2.1:1"), Sample{}, 1, 48)
	for i := 0; i < 6; i++ {
		l.Admit(NTP, ap("192.0.2.200:1"), Sample{}, 1, 48)
	}
	l.Flush()
	if len(r.scanner) != 1 || len(r.tend) != 1 {
		t.Fatalf("scanner=%d target_end=%d", len(r.scanner), len(r.tend))
	}
}

func TestIPv6Net(t *testing.T) {
	l, _, r := newTest(1000)
	for i := 0; i < 25; i++ {
		l.Admit(DNS, netip.MustParseAddrPort(fmt.Sprintf("[2001:db8:1:%x::1]:53", i)), Sample{}, 1, 60)
	}
	if len(r.nstart) != 1 || r.nstart[0].Prefix.Bits() != 48 {
		t.Fatalf("net_start = %+v", r.nstart)
	}
}

func blockNetAfterTarget(l *Limiter) {
	for i := 0; i < 6; i++ {
		l.Admit(NTP, ap("203.0.113.1:1"), Sample{}, 1, 48)
	}
	for i := 2; i < 21; i++ {
		l.Admit(NTP, netip.AddrPortFrom(netip.AddrFrom4([4]byte{203, 0, 113, byte(i)}), 1), Sample{}, 1, 48)
	}
}

func TestTargetEndAfterNetBlocks(t *testing.T) {
	l, c, r := newTest(1000)
	blockNetAfterTarget(l)
	if len(r.tstart) != 1 || len(r.nstart) != 1 {
		t.Fatalf("target_start=%d net_start=%d", len(r.tstart), len(r.nstart))
	}
	c.t = c.t.Add(11 * time.Minute)
	l.Tick()
	if len(r.tend) != 1 || r.tend[0].Addr.String() != "203.0.113.1" || len(r.nend) != 1 {
		t.Fatalf("tick: target_end=%+v net_end=%+v", r.tend, r.nend)
	}

	l, _, r = newTest(1000)
	blockNetAfterTarget(l)
	l.Flush()
	if len(r.tend) != 1 || r.tend[0].Addr.String() != "203.0.113.1" || len(r.nend) != 1 || len(r.scanner) != 0 {
		t.Fatalf("flush: target_end=%+v net_end=%+v scanner=%d", r.tend, r.nend, len(r.scanner))
	}
}

func TestByteBudgetBinds(t *testing.T) {
	cfg := Defaults(time.Minute)
	l, _, _ := newTest(100000)
	admit := func(i, size int) bool {
		return l.Admit(Chargen, netip.AddrPortFrom(netip.AddrFrom4([4]byte{10, byte(i), 0, 1}), 1), Sample{}, 1, size)
	}
	wantBig := int(cfg.GlobalBPS) / 2000
	n := 0
	for i := 0; i < wantBig; i++ {
		if !admit(n, 2000) {
			t.Fatalf("big admit %d refused", i+1)
		}
		n++
	}
	if admit(n, 2000) {
		t.Fatalf("admit %d of 2000 bytes allowed", wantBig+1)
	}
	n++
	wantSmall := int(cfg.GlobalPPS) - wantBig
	for i := 0; i < wantSmall; i++ {
		if !admit(n, 1) {
			t.Fatalf("small admit %d refused", i+1)
		}
		n++
	}
	if admit(n, 1) {
		t.Fatal("packet budget not enforced")
	}
}

func TestIPv4MappedSharesBudget(t *testing.T) {
	l, _, _ := newTest(1000)
	ok := 0
	for i := 0; i < 8; i++ {
		a := "203.0.113.5:1"
		if i%2 == 1 {
			a = "[::ffff:203.0.113.5]:1"
		}
		if l.Admit(NTP, ap(a), Sample{}, 1, 48) {
			ok++
		}
	}
	if ok != 5 {
		t.Fatalf("answers to one source in two spellings = %d, want 5", ok)
	}

	l, _, r := newTest(1000)
	ok = 0
	for i := 0; i < 30; i++ {
		a := fmt.Sprintf("203.0.113.%d:1", i)
		if i%2 == 1 {
			a = fmt.Sprintf("[::ffff:203.0.113.%d]:1", i)
		}
		if l.Admit(DNS, ap(a), Sample{}, 1, 60) {
			ok++
		}
	}
	if ok != 20 || len(r.nstart) != 1 || r.nstart[0].Prefix.String() != "203.0.113.0/24" {
		t.Fatalf("answers=%d net_start=%+v", ok, r.nstart)
	}
}

type safeObs struct{ mu sync.Mutex }

func (o *safeObs) Scanner(Source)     { o.mu.Lock(); o.mu.Unlock() }
func (o *safeObs) TargetStart(Source) { o.mu.Lock(); o.mu.Unlock() }
func (o *safeObs) TargetEnd(Source)   { o.mu.Lock(); o.mu.Unlock() }
func (o *safeObs) NetStart(Net)       { o.mu.Lock(); o.mu.Unlock() }
func (o *safeObs) NetEnd(Net)         { o.mu.Lock(); o.mu.Unlock() }

func TestConcurrentUse(t *testing.T) {
	cfg := Defaults(time.Millisecond)
	cfg.Window = 5 * time.Millisecond
	l := New(cfg, time.Now, &safeObs{})
	stop := time.Now().Add(200 * time.Millisecond)
	var wg sync.WaitGroup
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; time.Now().Before(stop); i++ {
				src := netip.AddrPortFrom(netip.AddrFrom4([4]byte{198, 51, byte(g), byte(i % 16)}), 1)
				l.Admit(Proto([]Proto{Chargen, DNS, NTP, SSDP}[i%4]), src, Sample{Req: []byte{1}}, 1, 64)
			}
		}(g)
	}
	wg.Add(2)
	go func() {
		defer wg.Done()
		for time.Now().Before(stop) {
			l.Tick()
			time.Sleep(time.Millisecond)
		}
	}()
	go func() {
		defer wg.Done()
		for time.Now().Before(stop) {
			l.Flush()
			time.Sleep(10 * time.Millisecond)
		}
	}()
	wg.Wait()
}

func TestNegativeSizesAddNoTokens(t *testing.T) {
	l, _, _ := newTest(100000)
	for i := 0; i < 50; i++ {
		l.Admit(Chargen, netip.AddrPortFrom(netip.AddrFrom4([4]byte{10, byte(i), 0, 1}), 1), Sample{}, 1, 1024)
	}
	if l.Admit(Chargen, ap("10.100.0.1:1"), Sample{}, 1, 1024) {
		t.Fatal("global budget not exhausted")
	}
	l.Admit(Chargen, ap("10.101.0.1:1"), Sample{}, -100, -100000)
	if l.Admit(Chargen, ap("10.102.0.1:1"), Sample{}, 1, 1024) {
		t.Fatal("negative sizes added tokens")
	}
}

// spendGlobal uses the packet budget of the instant with sources outside
// 203.0.113.0/24.
func spendGlobal(t *testing.T, l *Limiter) {
	t.Helper()
	for i := 0; i < 50; i++ {
		l.Admit(Chargen, netip.AddrPortFrom(netip.AddrFrom4([4]byte{10, byte(i), 0, 1}), 1), Sample{}, 1, 64)
	}
	if l.Admit(Chargen, ap("10.250.0.1:1"), Sample{}, 1, 64) {
		t.Fatal("global budget not spent")
	}
}

func TestSourceBudgetCountsRefusedPackets(t *testing.T) {
	l, c, r := newTest(1000)
	spendGlobal(t, l)
	for i := 0; i < 50; i++ {
		if l.Admit(NTP, ap("203.0.113.9:1"), Sample{}, 1, 48) {
			t.Fatalf("packet %d answered with the global budget spent", i+1)
		}
		if want := min(max(i-4, 0), 1); len(r.tstart) != want {
			t.Fatalf("after packet %d: target_start events = %d, want %d", i+1, len(r.tstart), want)
		}
	}
	c.t = c.t.Add(61 * time.Second)
	l.Tick()
	l.Flush()
	for _, s := range r.scanner {
		if s.Addr.String() == "203.0.113.9" {
			t.Fatalf("target reported as scanner: %+v", s)
		}
	}
	if len(r.tend) != 1 {
		t.Fatalf("target_end events = %d, want 1", len(r.tend))
	}
}

func TestNetBudgetCountsRefusedPackets(t *testing.T) {
	l, _, r := newTest(1000)
	spendGlobal(t, l)
	for i := 1; i <= 21; i++ {
		l.Admit(Chargen, netip.AddrPortFrom(netip.AddrFrom4([4]byte{203, 0, 113, byte(i)}), 1), Sample{}, 1, 64)
		if want := min(max(i-20, 0), 1); len(r.nstart) != want {
			t.Fatalf("after packet %d: net_start events = %d, want %d", i, len(r.nstart), want)
		}
	}
	if r.nstart[0].Packets != 21 || r.nstart[0].Prefix.String() != "203.0.113.0/24" {
		t.Fatalf("net_start = %+v", r.nstart[0])
	}
}

func TestPacketAfterNetBudgetBlocksNet(t *testing.T) {
	l, _, r := newTest(1000)
	for i := 1; i <= 4; i++ {
		for j := 0; j < 5; j++ {
			if !l.Admit(SSDP, netip.AddrPortFrom(netip.AddrFrom4([4]byte{203, 0, 113, byte(i)}), 1), Sample{}, 1, 100) {
				t.Fatalf("source %d: packet %d refused", i, j+1)
			}
		}
	}
	if l.Admit(SSDP, ap("203.0.113.1:1"), Sample{}, 1, 100) {
		t.Fatal("6th packet of a source answered")
	}
	if len(r.tstart) != 1 || len(r.nstart) != 1 || r.nstart[0].Packets != 21 {
		t.Fatalf("target_start=%d net_start=%+v", len(r.tstart), r.nstart)
	}
	if l.Admit(SSDP, ap("203.0.113.50:1"), Sample{}, 1, 100) {
		t.Fatal("answer inside a blocked net")
	}
}

func tcpSample() Sample { return Sample{Transport: "tcp"} }

func TestTCPSourceIsNoTarget(t *testing.T) {
	l, c, r := newTest(1000)
	ok := 0
	for i := 0; i < 30; i++ {
		if l.Admit(DNS, ap("198.51.100.30:5000"), tcpSample(), 0, 0) {
			ok++
		}
	}
	if ok != 5 {
		t.Fatalf("answers over TCP = %d, want 5", ok)
	}
	if len(r.tstart) != 0 || len(r.nstart) != 0 {
		t.Fatalf("target_start=%d net_start=%d", len(r.tstart), len(r.nstart))
	}
	c.t = c.t.Add(61 * time.Second)
	l.Tick()
	if len(r.scanner) != 1 || r.scanner[0].Packets != 30 || r.scanner[0].Sample.Transport != "tcp" {
		t.Fatalf("scanner = %+v", r.scanner)
	}
}

func TestTCPOutsideNetBudget(t *testing.T) {
	l, c, r := newTest(1000)
	for i := 1; i <= 10; i++ {
		for j := 0; j < 5; j++ {
			if !l.Admit(DNS, netip.AddrPortFrom(netip.AddrFrom4([4]byte{203, 0, 113, byte(i)}), 1), tcpSample(), 0, 0) {
				t.Fatalf("tcp source %d: query %d refused", i, j+1)
			}
		}
	}
	if len(r.nstart) != 0 {
		t.Fatal("TCP queries counted for the network")
	}
	for i := 100; i < 130; i++ {
		l.Admit(NTP, netip.AddrPortFrom(netip.AddrFrom4([4]byte{203, 0, 113, byte(i)}), 1), Sample{}, 1, 48)
	}
	if len(r.nstart) != 1 {
		t.Fatalf("net_start events = %d, want 1", len(r.nstart))
	}
	ok := 0
	for j := 0; j < 8; j++ {
		if l.Admit(DNS, ap("203.0.113.200:1"), tcpSample(), 0, 0) {
			ok++
		}
	}
	if ok != 5 {
		t.Fatalf("answers over TCP inside a blocked net = %d, want 5", ok)
	}
	c.t = c.t.Add(61 * time.Second)
	l.Tick()
	if len(r.scanner) != 11 {
		t.Fatalf("scanner events = %d, want 11 (the TCP sources)", len(r.scanner))
	}
}

func TestTCPAndUDPCountedApart(t *testing.T) {
	l, _, r := newTest(1000)
	for i := 0; i < 5; i++ {
		l.Admit(DNS, ap("198.51.100.40:1"), tcpSample(), 0, 0)
	}
	if !l.Admit(DNS, ap("198.51.100.40:1"), Sample{Transport: "udp"}, 1, 60) {
		t.Fatal("TCP queries counted for the UDP budget")
	}
	for i := 0; i < 5; i++ {
		l.Admit(DNS, ap("198.51.100.41:1"), Sample{Transport: "udp"}, 1, 60)
	}
	if len(r.tstart) != 0 {
		t.Fatal("target before the 6th UDP packet")
	}
	if !l.Admit(DNS, ap("198.51.100.41:1"), tcpSample(), 0, 0) {
		t.Fatal("UDP packets counted for the TCP budget")
	}
}

func TestOverMatchesAdmit(t *testing.T) {
	l, c, _ := newTest(1000)
	type pkt struct {
		src string
		tcp bool
	}
	var seq []pkt
	for round := 0; round < 8; round++ {
		for i := 1; i <= 4; i++ {
			seq = append(seq, pkt{fmt.Sprintf("203.0.113.%d:1", i), false})
		}
		seq = append(seq, pkt{"203.0.113.100:1", true}, pkt{"198.51.100.1:1", false})
	}
	seq = append(seq, pkt{"203.0.113.200:1", false}, pkt{"[::ffff:198.51.100.1]:1", false})
	for round := 0; round < 4; round++ { // 20 packets of 192.0.2.0/24, no source over its budget
		for i := 1; i <= 5; i++ {
			seq = append(seq, pkt{fmt.Sprintf("192.0.2.%d:1", i), false})
		}
	}
	seq = append(seq, pkt{"192.0.2.1:1", false}, pkt{"192.0.2.9:1", false})
	for i, p := range seq {
		s := Sample{Transport: "udp"}
		if p.tcp {
			s.Transport = "tcp"
		}
		over := l.Over(NTP, ap(p.src), p.tcp)
		if ok := l.Admit(NTP, ap(p.src), s, 0, 0); over == ok {
			t.Fatalf("packet %d from %s (tcp=%v): Over=%v Admit=%v", i+1, p.src, p.tcp, over, ok)
		}
		c.t = c.t.Add(time.Second)
	}
}

func TestOverChangesNothing(t *testing.T) {
	l, _, r := newTest(1000)
	for i := 0; i < 10; i++ {
		l.Over(NTP, ap("192.0.2.1:1"), false)
		l.Over(DNS, ap("192.0.2.2:1"), true)
	}
	if len(l.srcs) != 0 || len(l.tcpSrcs) != 0 || len(l.nets) != 0 || len(r.tstart) != 0 {
		t.Fatalf("Over created state: srcs=%d tcp=%d nets=%d", len(l.srcs), len(l.tcpSrcs), len(l.nets))
	}
	for i := 0; i < 5; i++ {
		if !l.Admit(NTP, ap("192.0.2.1:1"), Sample{}, 1, 48) {
			t.Fatalf("answer %d refused after Over", i+1)
		}
	}
}

func TestTCPTableSeparate(t *testing.T) {
	l, _, _ := newTest(3)
	l.cfg.MaxTCPSources = 3
	for i := 1; i <= 3; i++ {
		if !l.Admit(DNS, netip.AddrPortFrom(netip.AddrFrom4([4]byte{198, 51, 100, byte(i)}), 1), tcpSample(), 0, 0) {
			t.Fatalf("tcp source %d refused", i)
		}
	}
	if l.Admit(DNS, ap("198.51.100.4:1"), tcpSample(), 0, 0) {
		t.Fatal("tcp source answered with a full TCP table")
	}
	if !l.Over(DNS, ap("198.51.100.4:1"), true) {
		t.Fatal("Over false for a new tcp source with a full TCP table")
	}
	if !l.Admit(DNS, ap("198.51.100.5:1"), Sample{Transport: "udp"}, 1, 60) {
		t.Fatal("udp source refused with a full TCP table")
	}
}

func TestNoPlaceholderNet(t *testing.T) {
	l, _, _ := newTest(2)
	l.Admit(NTP, ap("192.0.2.1:1"), Sample{}, 1, 48)
	l.Admit(NTP, ap("192.0.2.2:1"), Sample{}, 1, 48)
	if l.Admit(NTP, ap("198.51.100.1:1"), Sample{}, 1, 48) {
		t.Fatal("answered with a full table")
	}
	if len(l.nets) != 1 {
		t.Fatalf("nets = %d, want 1", len(l.nets))
	}
}

func TestTickCost(t *testing.T) {
	l, c, r := newTest(200000)
	for i := 0; i < 200000; i++ {
		a := netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)})
		l.Admit(NTP, netip.AddrPortFrom(a, 1), Sample{}, 0, 0)
	}
	if len(l.srcs) != 200000 {
		t.Fatalf("sources = %d", len(l.srcs))
	}
	c.t = c.t.Add(30 * time.Second)
	limit := time.Millisecond
	if raceEnabled {
		limit = 20 * time.Millisecond
	}
	start := time.Now()
	l.Tick()
	if d := time.Since(start); d >= limit {
		t.Fatalf("Tick with nothing due took %v, want < %v", d, limit)
	}
	if len(r.scanner) != 0 || len(l.srcs) != 200000 {
		t.Fatalf("scanner=%d sources=%d", len(r.scanner), len(l.srcs))
	}
}

func TestTickOrderAfterRefresh(t *testing.T) {
	l, c, r := newTest(1000)
	l.Admit(NTP, ap("192.0.2.1:1"), Sample{}, 1, 48)
	c.t = c.t.Add(time.Second)
	l.Admit(NTP, ap("192.0.2.2:1"), Sample{}, 1, 48)
	c.t = c.t.Add(5 * time.Minute)
	l.Admit(NTP, ap("192.0.2.1:1"), Sample{}, 1, 48)
	c.t = c.t.Add(5 * time.Minute)
	l.Tick()
	if len(l.srcs) != 1 || len(r.scanner) != 2 {
		t.Fatalf("sources=%d scanner=%d, want 1/2", len(l.srcs), len(r.scanner))
	}
	if _, ok := l.srcs[srcKey{NTP, netip.MustParseAddr("192.0.2.1"), false}]; !ok {
		t.Fatal("refreshed source expired")
	}
	c.t = c.t.Add(5 * time.Minute)
	l.Tick()
	if len(l.srcs) != 0 || len(l.nets) != 0 {
		t.Fatalf("sources=%d nets=%d after the window", len(l.srcs), len(l.nets))
	}
}
