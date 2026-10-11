package dnspot

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/t3chn0m4g3/ddospot/internal/bucket"
)

func frozen() time.Time { return now }

// pipeDial returns a dial function whose connections are served in
// memory by answer; a nil answer closes the connection.
func pipeDial(dials *atomic.Int32, answer func(q *dns.Msg) *dns.Msg) func(context.Context) (*dns.Conn, error) {
	return func(context.Context) (*dns.Conn, error) {
		dials.Add(1)
		a, b := net.Pipe()
		go func() {
			defer b.Close()
			sc := &dns.Conn{Conn: b}
			for {
				q, err := sc.ReadMsg()
				if err != nil {
					return
				}
				r := answer(q)
				if r == nil || sc.WriteMsg(r) != nil {
					return
				}
			}
		}()
		return &dns.Conn{Conn: a}, nil
	}
}

func okAnswer(q *dns.Msg) *dns.Msg {
	m := new(dns.Msg)
	m.SetReply(q)
	m.Answer = []dns.RR{aRR(q.Question[0].Name, 300)}
	return m
}

func ask(d *DoT, name string) (*dns.Msg, error) {
	q := new(dns.Msg)
	q.SetQuestion(name, dns.TypeA)
	return d.Exchange(context.Background(), q)
}

func TestUpstreamInflightBound(t *testing.T) {
	d := NewDoT(time.Now)
	d.budget = bucket.New(1000, 1000)
	release := make(chan struct{})
	var dials atomic.Int32
	d.dial = func(ctx context.Context) (*dns.Conn, error) {
		dials.Add(1)
		<-release
		return nil, errors.New("closed")
	}
	var fast atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			t0 := time.Now()
			if _, err := ask(d, "x.example."); errors.Is(err, errBusy) && time.Since(t0) < 500*time.Millisecond {
				fast.Add(1)
			}
		}()
	}
	deadline := time.Now().Add(2 * time.Second)
	for (dials.Load() < 64 || fast.Load() < 36) && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if dials.Load() != 64 || fast.Load() != 36 {
		t.Fatalf("dials %d, busy %d", dials.Load(), fast.Load())
	}
	close(release)
	wg.Wait()
	if dials.Load() != 64 {
		t.Fatalf("dials %d", dials.Load())
	}
	if _, err := ask(d, "x.example."); errors.Is(err, errBusy) {
		t.Fatal("slots not given back")
	}
}

func TestHealthTransitions(t *testing.T) {
	d := NewDoT(time.Now)
	var fail atomic.Bool
	d.probe = func(context.Context) error {
		if fail.Load() {
			return errors.New("no answer")
		}
		return nil
	}
	ctx := context.Background()
	if d.Healthy() {
		t.Fatal("healthy before the first probe")
	}
	d.check(ctx)
	if !d.Healthy() {
		t.Fatal("not healthy after a good probe")
	}
	fail.Store(true)
	for i := 1; i <= 3; i++ {
		d.check(ctx)
		if want := i < 3; d.Healthy() != want {
			t.Fatalf("after %d failed probes healthy=%v", i, d.Healthy())
		}
	}
	d.check(ctx)
	if d.Healthy() {
		t.Fatal("healthy after 4 failed probes")
	}
	fail.Store(false)
	d.check(ctx)
	if !d.Healthy() {
		t.Fatal("not healthy after one good probe")
	}
	fail.Store(true)
	d.check(ctx)
	d.check(ctx)
	fail.Store(false)
	d.check(ctx)
	fail.Store(true)
	d.check(ctx)
	d.check(ctx)
	if !d.Healthy() {
		t.Fatal("a good probe does not reset the count")
	}
}

func TestRunProbesAtOnce(t *testing.T) {
	d := NewDoT(time.Now)
	var probes atomic.Int32
	d.probe = func(context.Context) error { probes.Add(1); return nil }
	d.interval = 20 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { d.Run(ctx); close(done) }()
	deadline := time.Now().Add(time.Second)
	for !d.Healthy() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !d.Healthy() {
		t.Fatal("not healthy")
	}
	for probes.Load() < 3 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if probes.Load() < 3 {
		t.Fatalf("probes %d", probes.Load())
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Run did not return")
	}
}

func TestDoTSettings(t *testing.T) {
	d := NewDoT(time.Now)
	c := d.client
	if c.Net != "tcp-tls" || c.Timeout != 2*time.Second || c.TLSConfig == nil ||
		c.TLSConfig.ServerName != "dns.quad9.net" || c.TLSConfig.MinVersion != tls.VersionTLS12 || c.TLSConfig.InsecureSkipVerify {
		t.Fatalf("%+v", c)
	}
	if cap(d.slots) != 64 || d.interval != 60*time.Second {
		t.Fatalf("slots %d interval %v", cap(d.slots), d.interval)
	}
	want := []string{"9.9.9.9:853", "149.112.112.112:853", "9.9.9.9:853", "149.112.112.112:853"}
	for i, w := range want {
		if got := d.nextServer(); got != w {
			t.Fatalf("server %d: %s", i, got)
		}
	}
}

func TestUpstreamBudget(t *testing.T) {
	d := NewDoT(frozen)
	var dials atomic.Int32
	d.dial = pipeDial(&dials, okAnswer)
	ok, spent := 0, 0
	for i := 0; i < 25; i++ {
		_, err := ask(d, "x.example.")
		switch {
		case err == nil:
			ok++
		case errors.Is(err, errBudget):
			spent++
		default:
			t.Fatal(err)
		}
	}
	if ok != 20 || spent != 5 {
		t.Fatalf("ok %d, budget %d", ok, spent)
	}
	d.now = func() time.Time { return now.Add(time.Second) }
	ok = 0
	for i := 0; i < 15; i++ {
		if _, err := ask(d, "x.example."); err == nil {
			ok++
		}
	}
	if ok != 10 {
		t.Fatalf("after 1 s: %d", ok)
	}
}

func TestConnReuse(t *testing.T) {
	d := NewDoT(time.Now)
	var dials atomic.Int32
	d.dial = pipeDial(&dials, okAnswer)
	for i := 0; i < 5; i++ {
		r, err := ask(d, "x.example.")
		if err != nil || len(r.Answer) != 1 {
			t.Fatalf("%v %v", err, r)
		}
	}
	if dials.Load() != 1 {
		t.Fatalf("dials %d", dials.Load())
	}
	conns := make([]*dns.Conn, 6)
	for i := range conns {
		conns[i], _ = d.dial(context.Background())
	}
	for _, c := range conns {
		d.put(c)
	}
	if len(d.idle) != 4 {
		t.Fatalf("idle %d", len(d.idle))
	}
	if _, err := conns[5].Write([]byte{0}); err == nil {
		t.Fatal("extra connection left open")
	}
}

func TestStaleConnRedials(t *testing.T) {
	d := NewDoT(time.Now)
	var dials, n atomic.Int32
	d.dial = pipeDial(&dials, func(q *dns.Msg) *dns.Msg {
		if n.Add(1) == 2 {
			return nil // the first connection ends after one answer
		}
		return okAnswer(q)
	})
	for i := 0; i < 2; i++ {
		if _, err := ask(d, "x.example."); err != nil {
			t.Fatalf("query %d: %v", i, err)
		}
	}
	if dials.Load() != 2 {
		t.Fatalf("dials %d", dials.Load())
	}
}

func TestAnswerMustMatch(t *testing.T) {
	d := NewDoT(time.Now)
	var dials atomic.Int32
	d.dial = pipeDial(&dials, func(q *dns.Msg) *dns.Msg {
		m := okAnswer(q)
		m.Question[0].Name = "other.example."
		return m
	})
	if _, err := ask(d, "x.example."); !errors.Is(err, errMismatch) {
		t.Fatalf("%v", err)
	}
	if len(d.idle) != 0 {
		t.Fatal("connection kept after a wrong answer")
	}
	d.dial = pipeDial(&dials, func(q *dns.Msg) *dns.Msg {
		m := okAnswer(q)
		m.Question[0].Name = "X.Example."
		return m
	})
	if _, err := ask(d, "x.example."); err != nil {
		t.Fatalf("case: %v", err)
	}
}

func TestExchangeTimeout(t *testing.T) {
	d := NewDoT(time.Now)
	d.timeout = 50 * time.Millisecond
	var dials atomic.Int32
	d.dial = pipeDial(&dials, func(q *dns.Msg) *dns.Msg { time.Sleep(time.Second); return okAnswer(q) })
	t0 := time.Now()
	if _, err := ask(d, "x.example."); err == nil {
		t.Fatal("answer after the timeout")
	}
	if time.Since(t0) > 500*time.Millisecond {
		t.Fatalf("took %v", time.Since(t0))
	}
}

func TestProbe(t *testing.T) {
	d := NewDoT(frozen)
	d.budget = bucket.New(0, 0)
	var dials atomic.Int32
	var got atomic.Value
	rcode := dns.RcodeSuccess
	d.dial = pipeDial(&dials, func(q *dns.Msg) *dns.Msg {
		got.Store(q.Question[0])
		m := okAnswer(q)
		m.Rcode = rcode
		return m
	})
	if err := d.probe(context.Background()); err != nil {
		t.Fatal(err)
	}
	if q := got.Load().(dns.Question); q.Name != "quad9.net." || q.Qtype != dns.TypeA || q.Qclass != dns.ClassINET {
		t.Fatalf("%v", q)
	}
	rcode = dns.RcodeServerFailure
	if err := d.probe(context.Background()); err == nil {
		t.Fatal("servfail counted as a good probe")
	}
}
