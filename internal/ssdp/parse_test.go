package ssdp

import (
	"strings"
	"testing"
)

func msearch(st, mx string) []byte {
	return []byte("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: " + mx + "\r\nST: " + st + "\r\n\r\n")
}

func TestParseMXClamped(t *testing.T) {
	r, ok := Parse(msearch("ssdp:all", "999999999"))
	if !ok || r.MX != 5 {
		t.Fatalf("%v %+v", ok, r)
	}
}

func TestParseRejects(t *testing.T) {
	for _, b := range [][]byte{nil, []byte("GET / HTTP/1.1\r\n\r\n"), []byte("M-SEARCH * HTTP/1.1\r\nST: ssdp:all\r\n\r\n")} {
		if _, ok := Parse(b); ok {
			t.Fatalf("accepted %q", b)
		}
	}
}

func TestParseFields(t *testing.T) {
	b := []byte("M-SEARCH * HTTP/1.1\r\nhost: 239.255.255.250:1900\r\nst:   upnp:rootdevice \t\r\nMan:\"ssdp:discover\"\r\nmx: 3\r\n\r\n")
	r, ok := Parse(b)
	if !ok {
		t.Fatal("rejected")
	}
	want := Request{ST: "upnp:rootdevice", MAN: `"ssdp:discover"`, Host: "239.255.255.250:1900", MX: 3, HasMX: true, MXRaw: "3"}
	if r != want {
		t.Fatalf("%+v", r)
	}
}

func TestParseMX(t *testing.T) {
	for _, c := range []struct {
		raw   string
		mx    int
		hasMX bool
	}{
		{"0", 0, true}, {"1", 1, true}, {"5", 5, true}, {"6", 5, true},
		{"+2", 2, true}, {"2s", 2, true}, {"99999999999999999999999", 5, true},
		{"-1", 0, false}, {"x", 0, false}, {"", 0, false}, {"-", 0, false},
	} {
		r, ok := Parse(msearch("ssdp:all", c.raw))
		if !ok || r.MX != c.mx || r.HasMX != c.hasMX || r.MXRaw != c.raw {
			t.Fatalf("%q: %v %+v", c.raw, ok, r)
		}
	}
	r, ok := Parse([]byte("M-SEARCH * HTTP/1.1\r\nMAN: \"ssdp:discover\"\r\nST: ssdp:all\r\n\r\n"))
	if !ok || r.HasMX || r.MX != 0 {
		t.Fatalf("without MX: %v %+v", ok, r)
	}
}

func TestParseRules(t *testing.T) {
	head := "M-SEARCH * HTTP/1.1\r\n"
	for _, c := range []struct {
		name string
		b    string
		ok   bool
	}{
		{"lower case method", "m-search * HTTP/1.1\r\nMAN: \"ssdp:discover\"\r\nST: ssdp:all\r\n\r\n", false},
		{"other path", "M-SEARCH / HTTP/1.1\r\nMAN: \"ssdp:discover\"\r\nST: ssdp:all\r\n\r\n", false},
		{"MAN without quotes", head + "MAN: ssdp:discover\r\nST: ssdp:all\r\n\r\n", false},
		{"MAN other value", head + "MAN: \"ssdp:update\"\r\nST: ssdp:all\r\n\r\n", false},
		{"empty ST", head + "MAN: \"ssdp:discover\"\r\nST:  \r\n\r\n", false},
		{"no CRLF after the request line", "M-SEARCH * HTTP/1.1", false},
		{"no final empty line", head + "MAN: \"ssdp:discover\"\r\nST: ssdp:all", true},
		{"no HOST", head + "MAN: \"ssdp:discover\"\r\nST: ssdp:all\r\n\r\n", true},
		{"space before the colon", head + "MAN: \"ssdp:discover\"\r\nST : ssdp:all\r\n\r\n", false},
	} {
		if _, ok := Parse([]byte(c.b)); ok != c.ok {
			t.Fatalf("%s: %v", c.name, ok)
		}
	}
}

func TestParseLastHeaderWins(t *testing.T) {
	r, ok := Parse([]byte("M-SEARCH * HTTP/1.1\r\nST: a\r\nMAN: \"ssdp:discover\"\r\nST: ssdp:all\r\n\r\n"))
	if !ok || r.ST != "ssdp:all" {
		t.Fatalf("%v %+v", ok, r)
	}
}

func TestParseValueEndsAtLineBreak(t *testing.T) {
	r, ok := Parse([]byte("M-SEARCH * HTTP/1.1\r\nMAN: \"ssdp:discover\"\r\nST: ssdp:all\nMX: 3\r\n\r\n"))
	if !ok || r.ST != "ssdp:all" || r.HasMX {
		t.Fatalf("%v %+v", ok, r)
	}
}

func TestParseHeaderCount(t *testing.T) {
	filler := strings.Repeat("X-A: b\r\n", 30)
	if _, ok := Parse([]byte("M-SEARCH * HTTP/1.1\r\n" + filler + "MAN: \"ssdp:discover\"\r\nST: ssdp:all\r\n\r\n")); !ok {
		t.Fatal("32 headers rejected")
	}
	filler += "X-A: b\r\n"
	if _, ok := Parse([]byte("M-SEARCH * HTTP/1.1\r\n" + filler + "MAN: \"ssdp:discover\"\r\nST: ssdp:all\r\n\r\n")); ok {
		t.Fatal("header 33 read")
	}
}

func TestParseReadsFirst2048Bytes(t *testing.T) {
	pad := "X-A: " + strings.Repeat("b", 2048) + "\r\n"
	if _, ok := Parse([]byte("M-SEARCH * HTTP/1.1\r\nMAN: \"ssdp:discover\"\r\n" + pad + "ST: ssdp:all\r\n\r\n")); ok {
		t.Fatal("header after byte 2048 read")
	}
	st := strings.Repeat("s", 2048)
	r, ok := Parse([]byte("M-SEARCH * HTTP/1.1\r\nMAN: \"ssdp:discover\"\r\nST: " + st + "\r\n\r\n"))
	if !ok || len(r.ST) != 2048-len("M-SEARCH * HTTP/1.1\r\nMAN: \"ssdp:discover\"\r\nST: ") {
		t.Fatalf("%v %d", ok, len(r.ST))
	}
}

func FuzzParse(f *testing.F) {
	f.Add(msearch("ssdp:all", "3"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		r, ok := Parse(b)
		if ok && (r.MX < 0 || r.MX > 5) {
			t.Fatal(r.MX)
		}
		if ok && len(Answer(per("debian11"), r, now)) > 8 {
			t.Fatal()
		}
	})
}
