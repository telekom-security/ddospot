package ntp

import (
	"encoding/binary"
	"math/rand"
	"net/netip"
	"testing"
	"time"
)

var monlist = []byte{0x17, 0x00, 0x03, 0x2a, 0, 0, 0, 0}

type entry struct {
	avg, last, restr, count uint32
	addr, daddr             netip.Addr
	flags                   uint32
	port                    uint16
	mode, version           uint8
}

func entries(t *testing.T, r [][]byte, impl, code byte, size int) []entry {
	t.Helper()
	var out []entry
	for i, d := range r {
		want := byte(0x80 | 2<<3 | 7)
		if i < len(r)-1 {
			want |= 0x40
		}
		if d[0] != want || int(d[1]) != i || d[2] != impl || d[3] != code {
			t.Fatalf("datagram %d header % x", i, d[:4])
		}
		n := int(binary.BigEndian.Uint16(d[4:]))
		if n>>12 != 0 || int(binary.BigEndian.Uint16(d[6:])) != size || len(d) != 8+n*size {
			t.Fatalf("datagram %d: items %x size %d length %d", i, n, binary.BigEndian.Uint16(d[6:]), len(d))
		}
		for k := 0; k < n; k++ {
			b := d[8+k*size : 8+(k+1)*size]
			e := entry{
				avg: binary.BigEndian.Uint32(b), last: binary.BigEndian.Uint32(b[4:]),
				restr: binary.BigEndian.Uint32(b[8:]), count: binary.BigEndian.Uint32(b[12:]),
				addr: netip.AddrFrom4([4]byte(b[16:20])),
			}
			off := 20
			if code == 42 {
				e.daddr = netip.AddrFrom4([4]byte(b[20:24]))
				e.flags = binary.BigEndian.Uint32(b[24:])
				off = 28
			}
			e.port, e.mode, e.version = binary.BigEndian.Uint16(b[off:]), b[off+2], b[off+3]
			for _, c := range b[off+4:] {
				if c != 0 {
					t.Fatal("IPv6 part not zero")
				}
			}
			out = append(out, e)
		}
	}
	return out
}

func TestMode7Entries(t *testing.T) {
	p := per("centos6")
	r, _ := Answer(p, monlist, src(), now, rand.New(rand.NewSource(2)))
	es := entries(t, r, 3, 42, 72)
	if len(es) != 1+len(p.Peers) {
		t.Fatalf("%d entries for %d peers", len(es), len(p.Peers))
	}
	me := es[0]
	if me != (entry{0, 0, 0x190, 1, src().Addr(), p.LAN, 1, src().Port(), 7, 2}) {
		t.Fatalf("requester %+v", me)
	}
	peers := map[netip.Addr]bool{}
	for _, a := range p.Peers {
		peers[a] = true
	}
	lan := netip.PrefixFrom(p.LAN, 24).Masked()
	for i, e := range es[1:] {
		if !peers[e.addr] {
			t.Fatalf("entry %s is no peer", e.addr)
		}
		delete(peers, e.addr)
		if i > 0 && e.last < es[i].last {
			t.Fatal("entries not most recent first")
		}
		mode := uint8(4)
		if lan.Contains(e.addr) {
			mode = 3
		}
		if e.mode != mode || e.version != 4 || e.port != 123 || e.daddr != p.LAN || e.flags != 1 || e.restr != 0x190 {
			t.Fatalf("peer %+v", e)
		}
		if e.count < 20 || e.count > 400 || e.avg < 32 || e.avg > 1024 || e.last >= 1024 {
			t.Fatalf("peer %+v", e)
		}
	}
}

// v6sizeof: a request of implementation 2 (IMPL_XNTPD_OLD) gets the items
// without the IPv6 part; MON_GETLIST (20) returns struct info_monitor.
func TestMode7ItemSizes(t *testing.T) {
	p := per("centos7")
	for _, c := range []struct {
		impl, code byte
		size       int
	}{{3, 42, 72}, {2, 42, 32}, {3, 20, 48}, {2, 20, 24}} {
		req := []byte{0x17, 0, c.impl, c.code, 0, 0, 0, 0}
		r, m := Answer(p, req, src(), now, rand.New(rand.NewSource(1)))
		if m != "MONLIST" {
			t.Fatal(m)
		}
		es := entries(t, r, c.impl, c.code, c.size)
		if len(es) != 1+len(p.Peers) || es[0].addr != src().Addr() || es[0].port != src().Port() || es[0].mode != 7 {
			t.Fatalf("%+v: %+v", c, es)
		}
	}
}

func TestMode7NotAnswered(t *testing.T) {
	p := per("centos6")
	for name, req := range map[string][]byte{
		"short":         monlist[:7],
		"response":      {0x97, 0, 3, 0x2a, 0, 0, 0, 0},
		"more":          {0x57, 0, 3, 0x2a, 0, 0, 0, 0},
		"version 0":     {0x07, 0, 3, 0x2a, 0, 0, 0, 0},
		"version 5":     {0x2f, 0, 3, 0x2a, 0, 0, 0, 0},
		"sequence":      {0x17, 1, 3, 0x2a, 0, 0, 0, 0},
		"error":         {0x17, 0, 3, 0x2a, 0x10, 0, 0, 0},
		"mbz":           {0x17, 0, 3, 0x2a, 0, 0, 0x10, 0},
		"item size":     {0x17, 0, 3, 0x2a, 0, 0, 0, 0x48},
		"impl 0":        {0x17, 0, 0, 0x2a, 0, 0, 0, 0},
		"other request": {0x17, 0, 3, 0x01, 0, 0, 0, 0},
	} {
		if r, _ := Answer(p, req, src(), now, rand.New(rand.NewSource(1))); r != nil {
			t.Fatalf("%s answered", name)
		}
	}
	v6 := netip.MustParseAddrPort("[2001:db8::1]:40123")
	if r, _ := Answer(p, monlist, v6, now, rand.New(rand.NewSource(1))); r != nil {
		t.Fatal("IPv6 requester answered")
	}
	mapped := netip.AddrPortFrom(netip.AddrFrom16(src().Addr().As16()), src().Port())
	r, _ := Answer(p, monlist, mapped, now, rand.New(rand.NewSource(1)))
	if es := entries(t, r, 3, 42, 72); es[0].addr != src().Addr() {
		t.Fatal("mapped requester")
	}
}

func TestMode7AtMostTwoDatagrams(t *testing.T) {
	p := *per("centos6")
	p.Peers = nil
	for i := 0; i < 30; i++ {
		p.Peers = append(p.Peers, netip.AddrFrom4([4]byte{198, 51, 100, byte(i + 1)}))
	}
	r, _ := Answer(&p, monlist, src(), now, rand.New(rand.NewSource(1)))
	if es := entries(t, r, 3, 42, 72); len(r) != 2 || len(es) != 12 {
		t.Fatalf("%d datagrams, %d entries", len(r), len(es))
	}
	req := []byte{0x17, 0, 3, 20, 0, 0, 0, 0}
	r, _ = Answer(&p, req, src(), now, rand.New(rand.NewSource(1)))
	for _, d := range r {
		if len(d) > 480 {
			t.Fatalf("datagram %d", len(d))
		}
	}
}

// The monitor list of one server moves on with the clock: counts grow,
// the addresses stay.
func TestMode7ListMovesOn(t *testing.T) {
	s := New(nil, nil, per("centos7"))
	t0 := time.Now()
	a, _ := s.answer(monlist, src(), t0)
	b, _ := s.answer(monlist, src(), t0.Add(3*time.Hour))
	ea, eb := entries(t, a, 3, 42, 72), entries(t, b, 3, 42, 72)
	if len(ea) != len(eb) {
		t.Fatal("entries changed")
	}
	count := map[netip.Addr]uint32{}
	for _, e := range ea[1:] {
		count[e.addr] = e.count
	}
	grew := 0
	for _, e := range eb[1:] {
		c, ok := count[e.addr]
		if !ok || e.count < c {
			t.Fatalf("%s: %d after %d", e.addr, e.count, c)
		}
		if e.count > c {
			grew++
		}
	}
	if grew == 0 {
		t.Fatal("no count grew in 3 hours")
	}
}
