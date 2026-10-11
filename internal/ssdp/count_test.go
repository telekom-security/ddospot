package ssdp

import (
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/t3chn0m4g3/ddospot/internal/limit"
	"github.com/t3chn0m4g3/ddospot/internal/persona"
	"github.com/t3chn0m4g3/ddospot/internal/testutil"
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

func countedTarget(t *testing.T, req []byte, src string) limit.Source {
	t.Helper()
	obs := &recObs{}
	s := New(nil, limit.New(limit.Defaults(time.Minute), time.Now, obs), per("debian11"))
	defer s.Close()
	a := netip.MustParseAddrPort(src)
	for i := 0; i < 5; i++ {
		s.handle(req, a)
	}
	if len(obs.targets) != 0 {
		t.Fatal("target after 5 datagrams")
	}
	s.handle(req, a)
	if len(obs.targets) != 1 {
		t.Fatalf("targets %d, want 1", len(obs.targets))
	}
	s.mu.Lock()
	n := len(s.timers)
	s.mu.Unlock()
	if n != 0 {
		t.Fatal("answer scheduled")
	}
	return obs.targets[0]
}

func TestUnmatchedSearchCounted(t *testing.T) {
	src := countedTarget(t, msearch("urn:x:y", "3"), "192.0.2.77:40000")
	f := src.Sample.Fields
	if f["st"] != "urn:x:y" || f["mx"] != "3" || src.Sample.RespSize != 0 {
		t.Fatalf("sample %+v", src.Sample)
	}
}

func TestUnparsableDatagramCounted(t *testing.T) {
	src := countedTarget(t, []byte("x"), "192.0.2.77:40000")
	f := src.Sample.Fields
	if f["st"] != "" || f["mx"] != "" {
		t.Fatalf("sample %+v", src.Sample)
	}
}

func TestIPv6DatagramCounted(t *testing.T) {
	src := countedTarget(t, msearch("ssdp:all", "1"), "[2001:db8::1]:40000")
	if src.Sample.Fields["st"] != "ssdp:all" {
		t.Fatalf("sample %+v", src.Sample)
	}
}

func TestOverSourceBuildsNothing(t *testing.T) {
	obs := &recObs{}
	lim := limit.New(limit.Defaults(time.Minute), time.Now, obs)
	srv, cli := testutil.UDPPair(t)
	s := New(srv, lim, per("debian11"))
	defer s.Close()
	built := 0
	inner := Answer
	s.answer = func(p *persona.Persona, r Request, now time.Time) [][]byte {
		built++
		return inner(p, r, now)
	}
	a := cli.LocalAddr().(*net.UDPAddr).AddrPort()
	for i := 0; i < 12; i++ {
		s.handle(msearch("upnp:rootdevice", "1"), a)
	}
	if built != 5 {
		t.Fatalf("answers built %d, want 5", built)
	}
	lim.Flush()
	if len(obs.ended) != 1 || obs.ended[0].Packets != 12 {
		t.Fatalf("ended %+v, want one source with 12 packets", obs.ended)
	}
}
