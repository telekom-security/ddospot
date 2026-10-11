package events

import (
	"encoding/base64"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/t3chn0m4g3/ddospot/internal/jsonlog"
	"github.com/t3chn0m4g3/ddospot/internal/limit"
	"github.com/t3chn0m4g3/ddospot/internal/testutil"
)

var readJSON = testutil.ReadJSON

func TestRolesAreSeparate(t *testing.T) {
	d := t.TempDir()
	w, _ := jsonlog.Open(d, time.Now)
	l := New(w, "debian11")
	src := limit.Source{Proto: limit.NTP, Addr: netip.MustParseAddr("192.0.2.1"), Port: 4000, First: time.Unix(0, 0), Last: time.Unix(90, 0), Packets: 9,
		Sample: limit.Sample{Transport: "udp", Req: []byte{1}, ReqSize: 1, Fields: map[string]any{"mode": "DATA"}}}
	l.Scanner(src)
	l.TargetStart(src)
	l.TargetEnd(src)
	w.Close()
	sc := readJSON(t, filepath.Join(d, "ntpot.log"))
	tg := readJSON(t, filepath.Join(d, "targets.log"))
	if len(sc) != 1 || sc[0]["src_ip"] != "192.0.2.1" || sc[0]["role"] != "scanner" || sc[0]["target_ip"] != nil {
		t.Fatalf("%v", sc)
	}
	if len(tg) != 2 || tg[0]["event"] != "attack_start" || tg[1]["event"] != "attack_end" || tg[1]["attack_seconds"] != float64(90) {
		t.Fatalf("%v", tg)
	}
	for _, e := range tg {
		if e["src_ip"] != nil || e["target_ip"] != "192.0.2.1" || e["dest_port"] != float64(123) {
			t.Fatalf("%v", e)
		}
	}
}

func wantKeys(t *testing.T, ev map[string]any, keys ...string) {
	t.Helper()
	if len(ev) != len(keys) {
		t.Errorf("keys %v, want %v", ev, keys)
	}
	for _, k := range keys {
		if _, ok := ev[k]; !ok {
			t.Errorf("key %s missing in %v", k, ev)
		}
	}
}

func TestScannerFields(t *testing.T) {
	d := t.TempDir()
	w, _ := jsonlog.Open(d, time.Now)
	l := New(w, "ubuntu2204")
	fields := map[string]any{"dns_name": "example.org.", "dns_type": "A"}
	src := limit.Source{Proto: limit.DNS, Addr: netip.MustParseAddr("2001:db8::7"), Port: 5353,
		First: time.Date(2026, 10, 11, 9, 8, 7, 123456000, time.UTC), Last: time.Date(2026, 10, 11, 9, 9, 0, 0, time.UTC), Packets: 3,
		Sample: limit.Sample{Transport: "tcp", Req: []byte("abc"), ReqSize: 700, RespSize: 99, Fields: fields}}
	l.Scanner(src)
	w.Close()
	ev := readJSON(t, filepath.Join(d, "dnspot.log"))
	if len(ev) != 1 {
		t.Fatalf("%v", ev)
	}
	e := ev[0]
	wantKeys(t, e, "time", "src_ip", "src_port", "role", "packets", "proto", "persona", "req_size", "resp_size", "req_pkt", "dns_name", "dns_type")
	if e["time"] != "2026-10-11 09:08:07.123456" || e["src_ip"] != "2001:db8::7" || e["src_port"] != float64(5353) ||
		e["packets"] != float64(3) || e["proto"] != "tcp" || e["persona"] != "ubuntu2204" || e["req_size"] != float64(700) ||
		e["resp_size"] != float64(99) || e["req_pkt"] != base64.StdEncoding.EncodeToString([]byte("abc")) || e["dns_name"] != "example.org." {
		t.Fatalf("%v", e)
	}
	if len(fields) != 2 {
		t.Fatalf("sample fields changed: %v", fields)
	}
}

func TestTargetFields(t *testing.T) {
	d := t.TempDir()
	w, _ := jsonlog.Open(d, time.Now)
	l := New(w, "debian11")
	fields := map[string]any{"st": "ssdp:all", "mx": 2}
	src := limit.Source{Proto: limit.SSDP, Addr: netip.MustParseAddr("198.51.100.4"), Port: 1900,
		First: time.Date(2026, 10, 11, 9, 0, 0, 0, time.UTC), Last: time.Date(2026, 10, 11, 9, 2, 30, 900000000, time.UTC), Packets: 40,
		Sample: limit.Sample{Transport: "udp", Req: []byte("M-SEARCH"), ReqSize: 8, RespSize: 300, Fields: fields}}
	l.TargetStart(src)
	l.TargetEnd(src)
	w.Close()
	ev := readJSON(t, filepath.Join(d, "targets.log"))
	if len(ev) != 2 {
		t.Fatalf("%v", ev)
	}
	start := []string{"event", "time", "role", "pot", "dest_port", "proto", "target_ip", "target_port", "persona", "first_seen", "packets", "req_size", "req_pkt", "st", "mx"}
	wantKeys(t, ev[0], start...)
	wantKeys(t, ev[1], append(start, "last_seen", "attack_seconds")...)
	s, e := ev[0], ev[1]
	if s["time"] != "2026-10-11 09:02:30.900000" || s["role"] != "target" || s["pot"] != "ssdp" || s["dest_port"] != float64(1900) ||
		s["target_port"] != float64(1900) || s["first_seen"] != "2026-10-11 09:00:00.000000" || s["packets"] != float64(40) || s["st"] != "ssdp:all" {
		t.Fatalf("%v", s)
	}
	if e["last_seen"] != "2026-10-11 09:02:30.900000" || e["attack_seconds"] != float64(150) {
		t.Fatalf("%v", e)
	}
	if len(fields) != 2 {
		t.Fatalf("sample fields changed: %v", fields)
	}
}

func TestNetEvents(t *testing.T) {
	d := t.TempDir()
	w, _ := jsonlog.Open(d, time.Now)
	l := New(w, "debian11")
	n := limit.Net{Prefix: netip.MustParsePrefix("203.0.113.0/24"), First: time.Date(2026, 10, 11, 8, 0, 0, 0, time.UTC),
		Last: time.Date(2026, 10, 11, 8, 10, 0, 0, time.UTC), Packets: 100, Sources: 7}
	l.NetStart(n)
	l.NetEnd(n)
	w.Close()
	ev := readJSON(t, filepath.Join(d, "targets.log"))
	if len(ev) != 2 {
		t.Fatalf("%v", ev)
	}
	start := []string{"event", "time", "role", "target_net", "sources", "packets", "first_seen", "persona"}
	wantKeys(t, ev[0], start...)
	wantKeys(t, ev[1], append(start, "last_seen", "attack_seconds")...)
	if ev[0]["event"] != "net_start" || ev[0]["target_net"] != "203.0.113.0/24" || ev[0]["sources"] != float64(7) ||
		ev[0]["time"] != "2026-10-11 08:10:00.000000" || ev[0]["role"] != "target" {
		t.Fatalf("%v", ev[0])
	}
	if ev[1]["event"] != "net_end" || ev[1]["attack_seconds"] != float64(600) || ev[1]["last_seen"] != "2026-10-11 08:10:00.000000" {
		t.Fatalf("%v", ev[1])
	}
}

func TestFilesAndPorts(t *testing.T) {
	for _, p := range []limit.Proto{limit.Chargen, limit.DNS, limit.NTP, limit.SSDP} {
		if Files[p] == "" || Ports[p] == 0 {
			t.Fatalf("%s: %q %d", p, Files[p], Ports[p])
		}
	}
}

var _ limit.Observer = (*Logger)(nil)

func TestDroppedEventsAreNotBuilt(t *testing.T) {
	d := t.TempDir()
	frozen := time.Unix(0, 0)
	w, _ := jsonlog.Open(d, func() time.Time { return frozen })
	defer w.Close()
	l := New(w, "debian11")
	src := limit.Source{Proto: limit.DNS, Addr: netip.MustParseAddr("192.0.2.1"), Port: 4000, First: frozen, Last: frozen, Packets: 1,
		Sample: limit.Sample{Transport: "udp", Req: make([]byte, 512), ReqSize: 700, Fields: map[string]any{"dns_name": "example.org."}}}
	n := limit.Net{Prefix: netip.MustParsePrefix("192.0.2.0/24"), First: frozen, Last: frozen, Packets: 1, Sources: 1}
	for i := 0; i < 400; i++ {
		l.NetStart(n)
	}
	w.Dropped()
	calls := []func(){func() { l.Scanner(src) }, func() { l.TargetStart(src) }, func() { l.TargetEnd(src) },
		func() { l.NetStart(n) }, func() { l.NetEnd(n) }}
	for i, f := range calls {
		if a := testing.AllocsPerRun(100, f); a != 0 {
			t.Errorf("call %d: %v allocations with the budget spent", i, a)
		}
	}
	w.Dropped()
	start := time.Now()
	for i := 0; i < 200000; i++ {
		l.Scanner(src)
	}
	if el := time.Since(start); el >= time.Second {
		t.Fatalf("200000 events took %v", el)
	}
	if got := w.Dropped(); got != 200000 {
		t.Fatalf("dropped %d, want 200000", got)
	}
}

func TestFlushOfFullTables(t *testing.T) {
	d := t.TempDir()
	frozen := time.Now()
	w, _ := jsonlog.Open(d, func() time.Time { return frozen })
	lim := limit.New(limit.Defaults(time.Hour), time.Now, New(w, "debian11"))
	s := limit.Sample{Transport: "udp", Req: make([]byte, 100), Fields: map[string]any{"mode": "client"}}
	for i := 0; i < 200000; i++ {
		a := netip.AddrFrom16([16]byte{0x20, 0x01, byte(i >> 16), byte(i >> 8), byte(i), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})
		lim.Admit(limit.NTP, netip.AddrPortFrom(a, 123), s, 0, 0)
	}
	start := time.Now()
	lim.Flush()
	w.Close()
	if el := time.Since(start); el >= time.Second {
		t.Fatalf("flush of 200000 sources took %v", el)
	} else {
		t.Logf("flush of 200000 sources: %v", el)
	}
	if ev := readJSON(t, filepath.Join(d, "ntpot.log")); len(ev) != 400 {
		t.Fatalf("lines %d, want 400", len(ev))
	}
	if got := w.Dropped(); got != 200000-400 {
		t.Fatalf("dropped %d", got)
	}
}
