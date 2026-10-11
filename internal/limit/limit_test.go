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
