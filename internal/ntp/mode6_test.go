package ntp

import (
	"encoding/binary"
	"math/rand"
	"regexp"
	"strings"
	"testing"

	"github.com/t3chn0m4g3/ddospot/internal/persona"
)

var readvar = []byte{0x16, 0x02, 0x00, 0x07, 0, 0, 0, 0, 0, 0, 0, 0}

// text joins the data of the fragments and checks their headers.
func text(t *testing.T, r [][]byte, seq uint16) string {
	t.Helper()
	var all strings.Builder
	for i, d := range r {
		if d[0] != 2<<3|6 {
			t.Fatalf("fragment %d: first byte %x", i, d[0])
		}
		want := byte(0x82)
		if i < len(r)-1 {
			want = 0xa2
		}
		if d[1] != want {
			t.Fatalf("fragment %d: op byte %x, want %x", i, d[1], want)
		}
		if binary.BigEndian.Uint16(d[2:]) != seq {
			t.Fatal("sequence")
		}
		if st := binary.BigEndian.Uint16(d[4:]); st != 0x0615 {
			t.Fatalf("status %04x", st)
		}
		if binary.BigEndian.Uint16(d[6:]) != 0 {
			t.Fatal("association")
		}
		if off := int(binary.BigEndian.Uint16(d[8:])); off != all.Len() {
			t.Fatalf("fragment %d: offset %d, want %d", i, off, all.Len())
		}
		n := int(binary.BigEndian.Uint16(d[10:]))
		if n > 468 || len(d) != (12+n+3)&^3 {
			t.Fatalf("fragment %d: count %d, length %d", i, n, len(d))
		}
		all.Write(d[12 : 12+n])
	}
	return all.String()
}

func names(s string) []string {
	var out []string
	for _, m := range regexp.MustCompile(`(?:^|, |,\r\n)([a-z_]+)=`).FindAllStringSubmatch(s, -1) {
		out = append(out, m[1])
	}
	return out
}

// The order of def_sys_var in ntp_control.c, with the variables an ntpd
// without leap second file, refclock and crypto prints.
const order = "version processor system leap stratum precision rootdelay rootdisp refid reftime clock peer tc mintc offset frequency sys_jitter clk_jitter clk_wander"

func TestMode6VariablesInOrder(t *testing.T) {
	for _, id := range []string{"centos6", "centos7", "debian11", "ubuntu2004"} {
		p := per(id)
		r, m := Answer(p, readvar, src(), now, rand.New(rand.NewSource(1)))
		if m != "CONTROL" {
			t.Fatal(m)
		}
		s := text(t, r, 7)
		if got := strings.Join(names(s), " "); got != order {
			t.Fatalf("%s: %s", id, got)
		}
		if !strings.HasSuffix(s, "\r\n") {
			t.Fatalf("%s: no trailing CRLF", id)
		}
		for _, want := range []string{
			`version="` + p.NTP.ReadvarVersion + `"`,
			`processor="` + p.NTP.Processor + `"`,
			`system="` + p.NTP.System + `"`,
			"leap=0,", "refid=" + p.RefID.String() + ",", "tc=10,", "mintc=3,",
		} {
			if !strings.Contains(s, want) {
				t.Fatalf("%s: no %q in %q", id, want, s)
			}
		}
		for _, re := range []string{`reftime=0x[0-9a-f]{8}\.[0-9a-f]{8},`, `clock=0x[0-9a-f]{8}\.[0-9a-f]{8},`, `rootdelay=\d+\.\d{3},`, `frequency=-?\d+\.\d{3},`, `peer=\d+,`} {
			if !regexp.MustCompile(re).MatchString(s) {
				t.Fatalf("%s: %s not in %q", id, re, s)
			}
		}
		// ctl_putdbl6 for offset and sys_jitter since 4.2.8, ctl_putdbl before.
		dec := `\d{6}`
		if p.NTP.Monlist {
			dec = `\d{3}`
		}
		for _, v := range []string{"offset", "sys_jitter"} {
			if !regexp.MustCompile(v + `=-?\d+\.` + dec + `,`).MatchString(s) {
				t.Fatalf("%s: %s in %q", id, v, s)
			}
		}
	}
}

// ctl_putdata starts a new line when an item would reach 72 columns.
func TestMode6LineBreaks(t *testing.T) {
	r, _ := Answer(per("debian11"), readvar, src(), now, rand.New(rand.NewSource(1)))
	s := strings.TrimSuffix(text(t, r, 7), "\r\n")
	for _, line := range strings.Split(s, "\r\n") {
		items := strings.Split(line, ", ")
		if len(items) > 1 && len(strings.TrimSuffix(line, ",")) >= 72 {
			t.Fatalf("line of %d columns: %q", len(line), line)
		}
	}
}

func long(id string, system string) *persona.Persona {
	p := *per(id)
	p.NTP.System = system
	return &p
}

// ntpd 4.2.8 fills a fragment up to less than 3 free bytes and may split
// an item between two fragments (ctl_putdata_ex);
// ntpd 4.2.6 moves the whole item into the next fragment and leaves the
// separator at the end of the first one (ctl_putdata).
func TestMode6Fragments(t *testing.T) {
	sys := "Linux/" + strings.Repeat("x", 300)
	r, _ := Answer(long("debian11", sys), readvar, src(), now, rand.New(rand.NewSource(1)))
	if len(r) != 2 || binary.BigEndian.Uint16(r[0][10:]) < 466 {
		t.Fatalf("4.2.8: %d fragments", len(r))
	}
	if s := text(t, r, 7); !strings.Contains(s, `system="`+sys+`"`) || names(s)[len(names(s))-1] != "clk_wander" {
		t.Fatalf("4.2.8: %q", s)
	}
	r, _ = Answer(long("centos6", sys), readvar, src(), now, rand.New(rand.NewSource(1)))
	if len(r) != 2 {
		t.Fatalf("4.2.6: %d fragments", len(r))
	}
	first := string(r[0][12 : 12+binary.BigEndian.Uint16(r[0][10:])])
	second := string(r[1][12:])
	if !strings.HasSuffix(first, ", ") && !strings.HasSuffix(first, ",\r\n") {
		t.Fatalf("4.2.6 first fragment ends %q", first[len(first)-4:])
	}
	if !regexp.MustCompile(`^[a-z_]+=`).MatchString(second) {
		t.Fatalf("4.2.6 second fragment starts %q", second[:10])
	}
	if s := text(t, r, 7); names(s)[len(names(s))-1] != "clk_wander" {
		t.Fatalf("4.2.6: %q", s)
	}
}

func TestMode6CutAtTwoFragments(t *testing.T) {
	for _, id := range []string{"debian11", "centos6"} {
		p := long(id, "Linux/"+strings.Repeat("y", 380))
		p.NTP.ReadvarVersion = strings.Repeat("v", 380)
		p.NTP.Processor = strings.Repeat("p", 380)
		r, _ := Answer(p, readvar, src(), now, rand.New(rand.NewSource(1)))
		if len(r) != 2 {
			t.Fatalf("%s: %d fragments", id, len(r))
		}
		s := text(t, r, 7)
		if !strings.HasSuffix(s, "\"\r\n") && !regexp.MustCompile(`[0-9a-f]\r\n$`).MatchString(s) {
			t.Fatalf("%s: ends %q", id, s[len(s)-10:])
		}
		n := names(s)
		if len(n) == 0 || len(n) >= len(strings.Fields(order)) {
			t.Fatalf("%s: %v", id, n)
		}
	}
}

func TestMode6NotAnswered(t *testing.T) {
	p := per("centos7")
	for name, mod := range map[string]func([]byte){
		"version 0":     func(b []byte) { b[0] = 6 },
		"version 5":     func(b []byte) { b[0] = 5<<3 | 6 },
		"response":      func(b []byte) { b[1] |= 0x80 },
		"error":         func(b []byte) { b[1] |= 0x40 },
		"more":          func(b []byte) { b[1] |= 0x20 },
		"association":   func(b []byte) { b[7] = 1 },
		"offset":        func(b []byte) { b[9] = 4 },
		"variable list": func(b []byte) { b[11] = 4 },
	} {
		req := append([]byte(nil), readvar...)
		mod(req)
		if name == "variable list" {
			req = append(req, 'l', 'e', 'a', 'p')
		}
		if r, _ := Answer(p, req, src(), now, rand.New(rand.NewSource(1))); r != nil {
			t.Fatalf("%s answered", name)
		}
	}
	if r, _ := Answer(p, readvar[:11], src(), now, rand.New(rand.NewSource(1))); r != nil {
		t.Fatal("short header answered")
	}
	if r, _ := Answer(p, append(append([]byte(nil), readvar...), 0), src(), now, rand.New(rand.NewSource(1))); r != nil {
		t.Fatal("length not a multiple of 4 answered")
	}
}
