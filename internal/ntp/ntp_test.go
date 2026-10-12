package ntp

import (
	"bytes"
	"math/rand"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/telekom-security/ddospot/internal/persona"
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

func src() netip.AddrPort { return netip.MustParseAddrPort("192.0.2.33:40123") }

func client(vn byte) []byte {
	b := make([]byte, 48)
	b[0] = vn<<3 | 3
	b[2] = 6
	copy(b[40:], []byte{1, 2, 3, 4, 5, 6, 7, 8})
	return b
}

func TestMode3EchoesVersionAndOrigin(t *testing.T) {
	for _, vn := range []byte{1, 2, 3, 4} {
		r, m := Answer(per("debian11"), client(vn), src(), now, rand.New(rand.NewSource(1)))
		if m != "DATA" || len(r) != 1 || len(r[0]) != 48 {
			t.Fatalf("vn %d: %d %v", vn, len(r), m)
		}
		if r[0][0] != vn<<3|4 {
			t.Fatalf("first byte %x", r[0][0])
		}
		if !bytes.Equal(r[0][24:32], []byte{1, 2, 3, 4, 5, 6, 7, 8}) {
			t.Fatal("origin")
		}
	}
}

func TestMode3Short(t *testing.T) {
	if r, _ := Answer(per("debian11"), client(4)[:47], src(), now, rand.New(rand.NewSource(1))); r != nil {
		t.Fatal()
	}
}

func TestReftimeSteps(t *testing.T) {
	p := per("debian11")
	s := New(nil, nil, p)
	a := s.reftime(now)
	b := s.reftime(now.Add(30 * time.Second))
	if !a.Equal(b) {
		t.Fatal("reftime moved within one poll step")
	}
	if c := s.reftime(now.Add(1100 * time.Second)); c.Equal(a) {
		t.Fatal("reftime stuck")
	}
}

func TestMode6Readvar(t *testing.T) {
	req := []byte{0x16, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, 0}
	r, m := Answer(per("centos7"), req, src(), now, rand.New(rand.NewSource(1)))
	if m != "CONTROL" || len(r) == 0 || len(r) > 2 {
		t.Fatalf("%v %d", m, len(r))
	}
	data := string(r[0][12:])
	if !strings.HasPrefix(data, `version="ntpd 4.2.6p5@1.2349-o`) || !strings.Contains(data, "stratum=2") {
		t.Fatalf("%q", data)
	}
	for _, d := range r {
		if len(d)%4 != 0 || len(d) > 12+468 {
			t.Fatalf("fragment size %d", len(d))
		}
	}
}

func TestMode6OtherOpcode(t *testing.T) {
	req := []byte{0x16, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, 0}
	if r, _ := Answer(per("centos7"), req, src(), now, rand.New(rand.NewSource(1))); r != nil {
		t.Fatal()
	}
}

func TestMode7OnlyOnOldNtp(t *testing.T) {
	req := []byte{0x17, 0x00, 0x03, 0x2a, 0, 0, 0, 0}
	if r, _ := Answer(per("debian11"), req, src(), now, rand.New(rand.NewSource(1))); r != nil {
		t.Fatal("4.2.8 persona answered mode 7")
	}
	r, m := Answer(per("centos6"), req, src(), now, rand.New(rand.NewSource(1)))
	if m != "MONLIST" || len(r) < 1 || len(r) > 2 {
		t.Fatalf("%v %d", m, len(r))
	}
	if got := netip.AddrFrom4([4]byte(r[0][8+16 : 8+20])); got != src().Addr() {
		t.Fatalf("first entry %s", got)
	}
	for _, d := range r {
		if (len(d)-8)%72 != 0 || (len(d)-8)/72 > 6 {
			t.Fatalf("datagram %d", len(d))
		}
	}
}

func FuzzAnswer(f *testing.F) {
	f.Add(client(4))
	f.Add([]byte{0x17, 0, 3, 0x2a, 0, 0, 0, 0})
	f.Add([]byte{0x16, 2, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0})
	f.Add([]byte{})
	p := per("centos6")
	f.Fuzz(func(t *testing.T, b []byte) {
		r, _ := Answer(p, b, src(), now, rand.New(rand.NewSource(1)))
		if len(r) > 2 {
			t.Fatal("more than 2 datagrams")
		}
		for _, d := range r {
			if len(d) > 480 {
				t.Fatalf("datagram %d", len(d))
			}
		}
	})
}
