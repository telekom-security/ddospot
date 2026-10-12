package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"

	dnspot "github.com/telekom-security/ddospot/internal/dns"
	"github.com/telekom-security/ddospot/internal/jsonlog"
	"github.com/telekom-security/ddospot/internal/testutil"
)

var readJSON = testutil.ReadJSON

// syncBuffer is a bytes.Buffer safe for concurrent use.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func captureStdout(t *testing.T) *syncBuffer {
	t.Helper()
	b := &syncBuffer{}
	old := stdout
	stdout = b
	t.Cleanup(func() { stdout = old })
	return b
}

func localConfig(d string) Config {
	return Config{LogDir: d, Recursion: false, Classify: time.Hour, Chargen: "127.0.0.1:0", DNS: "127.0.0.1:0", NTP: "127.0.0.1:0", SSDP: "127.0.0.1:0"}
}

// startApp runs the app in the background and returns its addresses and a
// function that stops it and returns the result of the run.
func startApp(t *testing.T, cfg Config) (Addrs, func() error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	addrs := make(chan Addrs, 1)
	done := make(chan error, 1)
	go func() { done <- runWithAddrs(ctx, cfg, nil, addrs) }()
	var a Addrs
	select {
	case a = <-addrs:
	case err := <-done:
		cancel()
		t.Fatal(err)
	}
	var once sync.Once
	var err error
	stop := func() error {
		once.Do(func() { cancel(); err = <-done })
		return err
	}
	t.Cleanup(func() { stop() })
	return a, stop
}

func TestShutdownFlushes(t *testing.T) {
	captureStdout(t)
	d := t.TempDir()
	cfg := Config{LogDir: d, Recursion: false, Classify: time.Hour, Chargen: "127.0.0.1:0", DNS: "127.0.0.1:0", NTP: "127.0.0.1:0", SSDP: "127.0.0.1:0"}
	ctx, cancel := context.WithCancel(context.Background())
	addrs := make(chan Addrs, 1)
	done := make(chan error, 1)
	go func() { done <- runWithAddrs(ctx, cfg, nil, addrs) }()
	a := <-addrs
	c, _ := net.Dial("udp", a.Chargen)
	c.Write([]byte("x"))
	c.Close()
	time.Sleep(100 * time.Millisecond)
	start := time.Now()
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("stop took longer than 2 s")
	}
	if ev := readJSON(t, filepath.Join(d, "chargenpot.log")); len(ev) != 1 {
		t.Fatalf("scanner events after stop: %d", len(ev))
	}
}

func TestFromEnv(t *testing.T) {
	env := map[string]string{"DDOSPOT_DNS_RECURSION": "off", "DDOSPOT_CLASSIFY_SECONDS": "2"}
	c, err := FromEnv(func(k string) string { return env[k] })
	if err != nil || c.Recursion || c.Classify != 2*time.Second || c.LogDir != "/var/log/ddospot" {
		t.Fatalf("%+v %v", c, err)
	}
	env["DDOSPOT_DNS_RECURSION"] = "yes"
	if _, err := FromEnv(func(k string) string { return env[k] }); err == nil {
		t.Fatal("accepted yes")
	}
}

func TestFromEnvDefaults(t *testing.T) {
	c, err := FromEnv(func(string) string { return "" })
	want := Config{LogDir: "/var/log/ddospot", Recursion: true, Classify: time.Minute, Chargen: ":19", DNS: ":53", NTP: ":123", SSDP: ":1900"}
	if err != nil || c != want {
		t.Fatalf("%+v %v", c, err)
	}
	c, err = FromEnv(func(k string) string {
		return map[string]string{"DDOSPOT_LOG_DIR": "/tmp/x", "DDOSPOT_DNS_RECURSION": "on", "DDOSPOT_CLASSIFY_SECONDS": "600"}[k]
	})
	if err != nil || c.LogDir != "/tmp/x" || !c.Recursion || c.Classify != 600*time.Second {
		t.Fatalf("%+v %v", c, err)
	}
}

func TestFromEnvClassifyRange(t *testing.T) {
	for _, v := range []string{"0", "601", "-1", "+5", "1.5", "abc", " 60", "60s"} {
		_, err := FromEnv(func(k string) string {
			if k == "DDOSPOT_CLASSIFY_SECONDS" {
				return v
			}
			return ""
		})
		if err == nil {
			t.Errorf("accepted %q", v)
		}
	}
	for _, v := range []string{"1", "600"} {
		if _, err := FromEnv(func(k string) string {
			if k == "DDOSPOT_CLASSIFY_SECONDS" {
				return v
			}
			return ""
		}); err != nil {
			t.Errorf("%q: %v", v, err)
		}
	}
}

func funcPtr(f any) uintptr { return reflect.ValueOf(f).Pointer() }

func TestDNSServerSettings(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	u, tc := newDNSServers(dns.HandlerFunc(func(dns.ResponseWriter, *dns.Msg) {}), pc, l, func() {})
	for _, s := range []*dns.Server{u, tc} {
		if s.MsgAcceptFunc == nil || funcPtr(s.MsgAcceptFunc) != funcPtr(dnspot.Accept) {
			t.Fatal("MsgAcceptFunc is not dnspot.Accept")
		}
		if s.DecorateReader == nil || funcPtr(s.DecorateReader) != funcPtr(dnspot.StrictReader) {
			t.Fatal("DecorateReader is not dnspot.StrictReader")
		}
		if s.NotifyStartedFunc == nil {
			t.Fatal("no NotifyStartedFunc")
		}
	}
	if u.PacketConn != pc || u.UDPSize != 4096 {
		t.Fatalf("udp server: %+v", u)
	}
	if tc.Listener == l || tc.Listener.Addr() != l.Addr() || tc.ReadTimeout != 5*time.Second || tc.MaxTCPQueries != 64 {
		t.Fatalf("tcp server: %+v", tc)
	}
}

func TestDNSAnswersWithinBudget(t *testing.T) {
	captureStdout(t)
	a, _ := startApp(t, localConfig(t.TempDir()))
	cl := &dns.Client{Timeout: 300 * time.Millisecond}
	got := 0
	for i := 0; i < 7; i++ {
		m := new(dns.Msg)
		m.SetQuestion("example.org.", dns.TypeA)
		m.Opcode = dns.OpcodeUpdate
		if r, _, err := cl.Exchange(m, a.DNS); err == nil {
			if r.Rcode != dns.RcodeNotImplemented {
				t.Fatalf("%v", r)
			}
			got++
		}
	}
	if got != 5 {
		t.Fatalf("udp answers %d, want 5", got)
	}
	c, err := net.Dial("udp", a.DNS)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Write([]byte{0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff})
	if n := testutil.ReadTimeout(c.(*net.UDPConn), 300*time.Millisecond); n != 0 {
		t.Fatalf("answer of %d bytes to a message that does not parse", n)
	}
}

func TestDNSOverTCP(t *testing.T) {
	captureStdout(t)
	a, _ := startApp(t, localConfig(t.TempDir()))
	m := new(dns.Msg)
	m.SetQuestion("version.bind.", dns.TypeTXT)
	m.Question[0].Qclass = dns.ClassCHAOS
	r, _, err := (&dns.Client{Net: "tcp", Timeout: time.Second}).Exchange(m, a.DNS)
	if err != nil || r.Rcode != dns.RcodeSuccess {
		t.Fatalf("%v %v", r, err)
	}
}

func TestDNSTCPConnectionsPerAddr(t *testing.T) {
	captureStdout(t)
	a, _ := startApp(t, localConfig(t.TempDir()))
	m := new(dns.Msg)
	m.SetQuestion("version.bind.", dns.TypeTXT)
	m.Question[0].Qclass = dns.ClassCHAOS
	for i := 0; i < tcpConnsPerAddr; i++ {
		co, err := dns.Dial("tcp", a.DNS)
		if err != nil {
			t.Fatal(err)
		}
		defer co.Close()
		co.SetDeadline(time.Now().Add(time.Second))
		if err := co.WriteMsg(m); err != nil {
			t.Fatal(err)
		}
		if r, err := co.ReadMsg(); err != nil || r.Rcode != dns.RcodeSuccess {
			t.Fatalf("connection %d: %v %v", i+1, r, err)
		}
	}
	c, err := net.Dial("tcp", a.DNS)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("connection %d kept open: %v", tcpConnsPerAddr+1, err)
	}
}

func TestStartupLine(t *testing.T) {
	out := captureStdout(t)
	_, stop := startApp(t, localConfig(t.TempDir()))
	if err := stop(); err != nil {
		t.Fatal(err)
	}
	s := out.String()
	if !strings.HasPrefix(s, "ddospot v2.0.0 persona=") || strings.Count(s, "\n") != 1 || len(s) <= len("ddospot v2.0.0 persona=\n") {
		t.Fatalf("%q", s)
	}
}

func TestListenError(t *testing.T) {
	captureStdout(t)
	busy, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	cfg := localConfig(t.TempDir())
	cfg.NTP = busy.LocalAddr().String()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := Run(ctx, cfg, nil); err == nil || ctx.Err() != nil {
		t.Fatalf("got %v, ctx %v", err, ctx.Err())
	}
}

func TestStopLeavesNoGoroutines(t *testing.T) {
	captureStdout(t)
	before := runtime.NumGoroutine()
	a, stop := startApp(t, localConfig(t.TempDir()))
	for _, addr := range []string{a.Chargen, a.NTP, a.SSDP, a.DNS} {
		c, _ := net.Dial("udp", addr)
		c.Write([]byte("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 5\r\nST: ssdp:all\r\n\r\n"))
		c.Close()
	}
	tc, err := net.Dial("tcp", a.DNS)
	if err != nil {
		t.Fatal(err)
	}
	defer tc.Close()
	time.Sleep(100 * time.Millisecond)
	start := time.Now()
	if err := stop(); err != nil {
		t.Fatal(err)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("stop took longer than 2 s")
	}
	deadline := time.Now().Add(time.Second)
	for runtime.NumGoroutine() > before && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if n := runtime.NumGoroutine(); n > before {
		buf := make([]byte, 1<<16)
		t.Fatalf("goroutines %d, before %d\n%s", n, before, buf[:runtime.Stack(buf, true)])
	}
}

func TestReport(t *testing.T) {
	d := t.TempDir()
	frozen := time.Now()
	w, err := jsonlog.Open(d, func() time.Time { return frozen })
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	var b bytes.Buffer
	report(&b, w)
	if b.Len() != 0 {
		t.Fatalf("%q", b.String())
	}
	w.Write("ntpot.log", map[string]any{"x": json.RawMessage("{")})
	for i := 0; i < 403; i++ {
		w.Write("ntpot.log", map[string]any{"i": i})
	}
	report(&b, w)
	if b.String() != "log lines dropped: 3\nlog write errors: 1\n" {
		t.Fatalf("%q", b.String())
	}
	b.Reset()
	report(&b, w)
	if b.Len() != 0 {
		t.Fatalf("%q", b.String())
	}
}

func TestReportUpstream(t *testing.T) {
	var b bytes.Buffer
	reportUpstream(&b, true, nil)
	reportUpstream(&b, false, errors.New("dial tcp 9.9.9.9:853: i/o timeout"))
	want := "dns upstream: answering, class IN resolved\n" +
		"dns upstream: not answering (dial tcp 9.9.9.9:853: i/o timeout), class IN answered with REFUSED\n"
	if b.String() != want {
		t.Fatalf("%q", b.String())
	}
}
