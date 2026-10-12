package ntp

import (
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/telekom-security/ddospot/internal/limit"
	"github.com/telekom-security/ddospot/internal/testutil"
)

// recObs keeps the events of the limiter.
type recObs struct {
	mu      sync.Mutex
	targets []limit.Source
	ended   []limit.Source
}

func (o *recObs) Scanner(limit.Source) {}
func (o *recObs) TargetStart(s limit.Source) {
	o.mu.Lock()
	o.targets = append(o.targets, s)
	o.mu.Unlock()
}
func (o *recObs) TargetEnd(s limit.Source) {
	o.mu.Lock()
	o.ended = append(o.ended, s)
	o.mu.Unlock()
}
func (o *recObs) NetStart(limit.Net) {}
func (o *recObs) NetEnd(limit.Net)   {}

func TestModeName(t *testing.T) {
	for _, c := range []struct {
		req  []byte
		want string
	}{
		{client(4), "DATA"},
		{[]byte{0x0b, 0}, "DATA"}, // version 1, mode 0
		{[]byte{0x20, 0}, "OTHER"},
		{[]byte{0x16, 2}, "CONTROL"},
		{[]byte{0x17, 0, 3, 42}, "MONLIST"},
		{[]byte{0x1d, 0}, "OTHER"}, // mode 5
		{[]byte{0x17}, "MONLIST"},
		{nil, "OTHER"},
	} {
		if got := modeName(c.req); got != c.want {
			t.Errorf("%x: %q, want %q", c.req, got, c.want)
		}
	}
}

func TestUnansweredDatagramsCounted(t *testing.T) {
	obs := &recObs{}
	lim := limit.New(limit.Defaults(time.Minute), time.Now, obs)
	s := New(nil, lim, per("debian11"))
	a := netip.MustParseAddrPort("192.0.2.77:40000")
	mode7 := []byte{0x17, 0x00, 0x03, 0x2a, 0, 0, 0, 0}
	for i := 0; i < 5; i++ {
		s.handle(mode7, a)
	}
	if len(obs.targets) != 0 {
		t.Fatal("target after 5 datagrams")
	}
	s.handle(mode7, a)
	if len(obs.targets) != 1 {
		t.Fatalf("targets %d, want 1", len(obs.targets))
	}
	f := obs.targets[0].Sample.Fields
	if f["mode"] != "MONLIST" || obs.targets[0].Sample.RespSize != 0 {
		t.Fatalf("sample %+v", obs.targets[0].Sample)
	}
	b := netip.MustParseAddrPort("192.0.2.78:40000")
	for i := 0; i < 6; i++ {
		s.handle([]byte{0x1d, 0}, b)
	}
	if len(obs.targets) != 2 || obs.targets[1].Sample.Fields["mode"] != "OTHER" {
		t.Fatalf("targets %+v", obs.targets)
	}
}

func TestOverSourceBuildsNothing(t *testing.T) {
	obs := &recObs{}
	lim := limit.New(limit.Defaults(time.Minute), time.Now, obs)
	srv, cli := testutil.UDPPair(t)
	s := New(srv, lim, per("debian11"))
	built := 0
	s.build = func(req []byte, src netip.AddrPort, now time.Time) ([][]byte, string) {
		built++
		return s.answer(req, src, now)
	}
	a := cli.LocalAddr().(*net.UDPAddr).AddrPort()
	for i := 0; i < 12; i++ {
		s.handle(client(4), a)
	}
	if built != 5 {
		t.Fatalf("answers built %d, want 5", built)
	}
	lim.Flush()
	if len(obs.ended) != 1 || obs.ended[0].Packets != 12 {
		t.Fatalf("ended %+v, want one source with 12 packets", obs.ended)
	}
	if got := obs.ended[0].Sample.Fields["mode"]; got != "DATA" {
		t.Fatalf("mode %v", got)
	}
}
