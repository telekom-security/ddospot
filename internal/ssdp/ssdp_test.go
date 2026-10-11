package ssdp

import (
	"bytes"
	"fmt"
	"math/rand"
	"net/netip"
	"strings"
	"testing"
	"time"

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

func loc(p *persona.Persona) string {
	return fmt.Sprintf("http://%s:%d%s", p.LAN, p.SSDPPort, p.SSDP.Path)
}

// upnpd is the answer of miniupnpd 2.2.1 for one st and usn.
func upnpd(p *persona.Persona, st, usn string) string {
	return "HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=120\r\nST: " + st + "\r\nUSN: " + usn +
		"\r\nEXT:\r\nSERVER: " + p.SSDP.Server + "\r\nLOCATION: " + loc(p) +
		"\r\nOPT: \"http://schemas.upnp.org/upnp/1/0/\"; ns=01\r\n" +
		fmt.Sprintf("01-NLS: %d\r\nBOOTID.UPNP.ORG: %d\r\nCONFIGID.UPNP.ORG: %d\r\n\r\n", p.BootID, p.BootID, p.ConfigID)
}

// dlna is the answer of minidlna for one st and usn.
func dlna(p *persona.Persona, st, usn string) string {
	return "HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=1810\r\nDATE: Sun, 11 Oct 2026 09:08:07 GMT\r\nST: " + st +
		"\r\nUSN: " + usn + "\r\nEXT:\r\nSERVER: " + p.SSDP.Server + "\r\nLOCATION: " + loc(p) +
		"\r\nContent-Length: 0\r\n\r\n"
}

func strs(resp [][]byte) []string {
	out := make([]string, len(resp))
	for i, d := range resp {
		out[i] = string(d)
	}
	return out
}

func same(t *testing.T, got [][]byte, want ...string) {
	t.Helper()
	g := strs(got)
	if len(g) != len(want) {
		t.Fatalf("%d datagrams, want %d:\n%q", len(g), len(want), g)
	}
	for i := range want {
		if g[i] != want[i] {
			t.Fatalf("datagram %d:\n got %q\nwant %q", i, g[i], want[i])
		}
	}
}

func ask(p *persona.Persona, st string) [][]byte {
	r, ok := Parse(msearch(st, "1"))
	if !ok {
		panic(st)
	}
	return Answer(p, r, now)
}

func TestAnswerAllWithinLimit(t *testing.T) {
	for _, id := range []string{"centos6", "debian11"} {
		p := per(id)
		r, _ := Parse(msearch("ssdp:all", "1"))
		resp := Answer(p, r, now)
		if len(resp) == 0 || len(resp) > 8 {
			t.Fatalf("%s: %d", id, len(resp))
		}
		for _, d := range resp {
			if !bytes.HasSuffix(d, []byte("\r\n\r\n")) || !bytes.Contains(d, []byte("SERVER: "+p.SSDP.Server+"\r\n")) {
				t.Fatalf("%q", d)
			}
		}
	}
}

func TestAnswerUnknownST(t *testing.T) {
	r, _ := Parse(msearch("urn:x:y", "1"))
	if Answer(per("debian11"), r, now) != nil {
		t.Fatal()
	}
}

func TestMiniupnpdRootDevice(t *testing.T) {
	p := per("debian11")
	u := "uuid:" + p.UUIDs[0]
	same(t, ask(p, "upnp:rootdevice"), upnpd(p, "upnp:rootdevice", u+"::upnp:rootdevice"))
}

func TestMiniupnpdTypesKeepTheVersionAsked(t *testing.T) {
	p := per("debian11")
	igd, wan, wcd := "uuid:"+p.UUIDs[0], "uuid:"+p.UUIDs[1], "uuid:"+p.UUIDs[2]
	for _, c := range []struct{ st, uuid string }{
		{"urn:schemas-upnp-org:device:InternetGatewayDevice:2", igd},
		{"urn:schemas-upnp-org:device:InternetGatewayDevice:1", igd},
		{"urn:schemas-upnp-org:device:WANDevice:1", wan},
		{"urn:schemas-upnp-org:device:WANConnectionDevice:2", wcd},
		{"urn:schemas-upnp-org:service:WANIPConnection:1", wcd},
		{"urn:schemas-upnp-org:service:WANPPPConnection:1", wcd},
		{"urn:schemas-upnp-org:service:WANCommonInterfaceConfig:1", wan},
		{"urn:schemas-upnp-org:service:Layer3Forwarding:1", igd},
		{"urn:schemas-upnp-org:service:DeviceProtection:1", igd},
		{"urn:schemas-upnp-org:service:WANIPv6FirewallControl:1", wcd},
	} {
		same(t, ask(p, c.st), upnpd(p, c.st, c.uuid+"::"+c.st))
	}
}

func TestMiniupnpdUUID(t *testing.T) {
	p := per("debian11")
	for _, u := range p.UUIDs {
		same(t, ask(p, "uuid:"+u), upnpd(p, "uuid:"+u, "uuid:"+u))
	}
	if ask(p, "uuid:"+strings.ToUpper(p.UUIDs[0])) != nil {
		t.Fatal("uuid compared without case")
	}
	if ask(p, "uuid:"+p.UUIDs[0]+"0") != nil {
		t.Fatal("longer uuid answered")
	}
}

func TestMiniupnpdAllInTableOrder(t *testing.T) {
	p := per("debian11")
	igd, wan, wcd := "uuid:"+p.UUIDs[0], "uuid:"+p.UUIDs[1], "uuid:"+p.UUIDs[2]
	d, s := "urn:schemas-upnp-org:device:", "urn:schemas-upnp-org:service:"
	want := []string{}
	for _, c := range []struct{ st, uuid string }{
		{"upnp:rootdevice", igd},
		{d + "InternetGatewayDevice:2", igd},
		{d + "WANConnectionDevice:2", wcd},
		{d + "WANDevice:2", wan},
		{s + "WANIPConnection:2", wcd},
		{s + "DeviceProtection:1", igd},
		{s + "WANIPv6FirewallControl:1", wcd},
		{s + "WANCommonInterfaceConfig:1", wan},
	} {
		want = append(want, upnpd(p, c.st, c.uuid+"::"+c.st))
	}
	same(t, ask(p, "ssdp:all"), want...)
}

func TestMiniupnpdLongSTCut(t *testing.T) {
	p := per("debian11")
	st := "upnp:rootdevice" + strings.Repeat("x", 1500)
	resp := ask(p, st)
	if len(resp) != 1 || len(resp[0]) != 1023 || !strings.HasPrefix(string(resp[0]), "HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=120\r\nST: "+st[:900]) {
		t.Fatalf("%d %q", len(resp), resp)
	}
}

func TestMinidlnaTargets(t *testing.T) {
	for _, id := range []string{"centos6", "centos7", "ubuntu2004"} {
		p := per(id)
		u := "uuid:" + p.UUIDs[0]
		ms := "urn:schemas-upnp-org:device:MediaServer:1"
		cd := "urn:schemas-upnp-org:service:ContentDirectory:1"
		same(t, ask(p, u), dlna(p, u, u))
		same(t, ask(p, "upnp:rootdevice"), dlna(p, "upnp:rootdevice", u+"::upnp:rootdevice"))
		same(t, ask(p, ms), dlna(p, ms, u+"::"+ms))
		same(t, ask(p, cd), dlna(p, cd, u+"::"+cd))
		// minidlna answers a type without version with version 1.
		same(t, ask(p, "urn:schemas-upnp-org:device:MediaServer:"), dlna(p, ms, u+"::"+ms))
		for _, st := range []string{
			"urn:schemas-upnp-org:device:MediaServer:2",
			"urn:schemas-upnp-org:device:MediaServer:10",
			"urn:schemas-upnp-org:device:MediaServer:1x",
			"upnp:rootdevicex",
			"urn:schemas-upnp-org:device:InternetGatewayDevice:1",
			"uuid:" + strings.ToUpper(p.UUIDs[0]),
		} {
			if r := ask(p, st); r != nil {
				t.Fatalf("%s %s: %q", id, st, r)
			}
		}
	}
}

func TestMinidlnaAll(t *testing.T) {
	p := per("centos7")
	u := "uuid:" + p.UUIDs[0]
	want := []string{dlna(p, u, u), dlna(p, "upnp:rootdevice", u+"::upnp:rootdevice")}
	for _, st := range []string{
		"urn:schemas-upnp-org:device:MediaServer:1",
		"urn:schemas-upnp-org:service:ContentDirectory:1",
		"urn:schemas-upnp-org:service:ConnectionManager:1",
		"urn:microsoft.com:service:X_MS_MediaReceiverRegistrar:1",
	} {
		want = append(want, dlna(p, st, u+"::"+st))
	}
	same(t, ask(p, "ssdp:all"), want...)
}

func TestMinidlnaNeedsMX(t *testing.T) {
	p := per("centos6")
	for _, mx := range []string{"", "x", "-1"} {
		r, ok := Parse(msearch("ssdp:all", mx))
		if !ok || Answer(p, r, now) != nil {
			t.Fatalf("MX %q answered", mx)
		}
	}
	r, _ := Parse([]byte("M-SEARCH * HTTP/1.1\r\nMAN: \"ssdp:discover\"\r\nST: ssdp:all\r\n\r\n"))
	if Answer(p, r, now) != nil {
		t.Fatal("answer without MX")
	}
	// miniupnpd does not read MX.
	if Answer(per("debian11"), r, now) == nil {
		t.Fatal("miniupnpd: no answer without MX")
	}
}

func TestDelay(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	all, _ := Parse(msearch("ssdp:all", "5"))
	one, _ := Parse(msearch("upnp:rootdevice", "5"))
	for _, c := range []struct {
		id       string
		r        Request
		min, max time.Duration
	}{
		{"debian11", all, 50 * time.Millisecond, 50 * time.Millisecond},
		{"debian11", one, 50 * time.Millisecond, 50 * time.Millisecond},
		{"centos6", all, 0, 0},
		{"ubuntu2004", all, 0, 0},
		{"centos6", one, 0, 2047 * time.Microsecond},
		{"ubuntu2004", one, 0, 2047 * time.Microsecond},
		{"centos7", one, 13 * time.Millisecond, 20 * time.Millisecond},
		{"centos7", all, 13 * time.Millisecond, 30 * time.Millisecond},
	} {
		p := per(c.id)
		for i := 0; i < 200; i++ {
			if d := delay(p, c.r, rng); d < c.min || d > c.max {
				t.Fatalf("%s %s: %v", c.id, c.r.ST, d)
			}
		}
	}
}

func TestCloseIsQuick(t *testing.T) {
	srv, cli := testutil.UDPPair(t)
	p := per("debian11")
	s := New(srv, limit.New(limit.Defaults(time.Minute), time.Now, testutil.NopObs{}), p)
	go s.Serve()
	cli.Write(msearch("ssdp:all", "5"))
	time.Sleep(50 * time.Millisecond)
	start := time.Now()
	s.Close()
	srv.Close()
	if time.Since(start) > 200*time.Millisecond {
		t.Fatal("close waited for the answer delay")
	}
}

func TestServeAnswersAfterDelay(t *testing.T) {
	srv, cli := testutil.UDPPair(t)
	p := per("debian11")
	s := New(srv, limit.New(limit.Defaults(time.Minute), time.Now, testutil.NopObs{}), p)
	go s.Serve()
	defer s.Close()
	start := time.Now()
	cli.Write(msearch("ssdp:all", "1"))
	n := 0
	for testutil.ReadTimeout(cli, 300*time.Millisecond) > 0 {
		if n++; n == 1 && time.Since(start) < 40*time.Millisecond {
			t.Fatal("answer before the delay")
		}
	}
	if n != 8 {
		t.Fatalf("%d datagrams", n)
	}
}

func TestServeCountsInvalid(t *testing.T) {
	srv, cli := testutil.UDPPair(t)
	s := New(srv, limit.New(limit.Defaults(time.Minute), time.Now, testutil.NopObs{}), per("centos7"))
	go s.Serve()
	defer s.Close()
	for _, b := range [][]byte{[]byte("x"), msearch("urn:x:y", "1"), msearch("ssdp:all", "")} {
		cli.Write(b)
		if testutil.ReadTimeout(cli, 150*time.Millisecond) != 0 {
			t.Fatalf("answer to %q", b)
		}
	}
	// Each of them is one of the five packets of the source.
	got := 0
	for i := 0; i < 6; i++ {
		cli.Write(msearch("upnp:rootdevice", "1"))
		if testutil.ReadTimeout(cli, 200*time.Millisecond) > 0 {
			got++
		}
	}
	if got != 2 {
		t.Fatalf("answers %d, want 2", got)
	}
}

func TestCloseDropsPendingAnswers(t *testing.T) {
	srv, cli := testutil.UDPPair(t)
	s := New(srv, limit.New(limit.Defaults(time.Minute), time.Now, testutil.NopObs{}), per("debian11"))
	go s.Serve()
	cli.Write(msearch("ssdp:all", "5"))
	time.Sleep(10 * time.Millisecond)
	s.Close()
	if testutil.ReadTimeout(cli, 200*time.Millisecond) != 0 {
		t.Fatal("answer after Close")
	}
	s.Close() // a second Close is harmless
}

func TestServeIgnoresIPv6(t *testing.T) {
	s := New(nil, limit.New(limit.Defaults(time.Minute), time.Now, testutil.NopObs{}), per("debian11"))
	s.handle(msearch("ssdp:all", "1"), netip.MustParseAddrPort("[2001:db8::1]:40000"))
	s.mu.Lock()
	n := len(s.timers)
	s.mu.Unlock()
	if n != 0 {
		t.Fatal("answer scheduled for an IPv6 source")
	}
}
