package dnspot

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"

	"github.com/t3chn0m4g3/ddospot/internal/bucket"
)

// Upstream resolves the questions the persona answers recursively.
type Upstream interface {
	Exchange(ctx context.Context, q *dns.Msg) (*dns.Msg, error)
	Healthy() bool
}

const (
	quad9Name   = "dns.quad9.net"
	queryTime   = 2 * time.Second
	maxInflight = 64
	maxIdle     = 4
	probeEvery  = 60 * time.Second // while healthy
	probeRetry  = 10 * time.Second // while unhealthy
	probeFails  = 3                // failed probes in a row before the upstream counts as down
	budgetRate  = 10
	budgetBurst = 20
)

var quad9 = []string{"9.9.9.9:853", "149.112.112.112:853"}

var (
	errBusy     = errors.New("dnspot: upstream queries in flight at the limit")
	errBudget   = errors.New("dnspot: upstream query budget spent")
	errMismatch = errors.New("dnspot: upstream answer does not match the question")
)

// DoT is the Quad9 resolver over DNS over TLS. It keeps up to 4 idle
// connections, sends at most 10 queries per second (burst 20) with at
// most 64 in flight, and probes the servers every 60 s while they answer
// and every 10 s while they do not.
type DoT struct {
	// Report, when set before Run, is called on every change of the
	// health: up after a good probe, down with the last error after the
	// third failed probe in a row.
	Report func(up bool, err error)

	now      func() time.Time
	dial     func(ctx context.Context) (*dns.Conn, error)
	probe    func(ctx context.Context) error
	interval time.Duration // between probes while healthy
	retry    time.Duration // between probes while unhealthy
	timeout  time.Duration
	client   *dns.Client
	slots    chan struct{}
	healthy  atomic.Bool

	mu     sync.Mutex // guards the fields below
	budget *bucket.Bucket
	idle   []*dns.Conn
	next   int
	fails  int
	state  int8 // health last reported: 0 none yet, 1 up, -1 down
	closed bool
}

// NewDoT returns the Quad9 resolver, unhealthy until Run's first probe
// gets an answer.
func NewDoT(now func() time.Time) *DoT {
	d := &DoT{
		now:      now,
		interval: probeEvery,
		retry:    probeRetry,
		timeout:  queryTime,
		client: &dns.Client{
			Net:       "tcp-tls",
			TLSConfig: &tls.Config{ServerName: quad9Name, MinVersion: tls.VersionTLS12},
			Timeout:   queryTime,
		},
		slots:  make(chan struct{}, maxInflight),
		budget: bucket.New(budgetRate, budgetBurst),
	}
	d.dial = func(ctx context.Context) (*dns.Conn, error) { return d.client.DialContext(ctx, d.nextServer()) }
	d.probe = d.probeOnce
	return d
}

// nextServer returns the Quad9 addresses in turn.
func (d *DoT) nextServer() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	s := quad9[d.next%len(quad9)]
	d.next++
	return s
}

// Healthy reports whether the last probes got answers.
func (d *DoT) Healthy() bool { return d.healthy.Load() }

// Exchange sends q upstream within the query budget and the bound of
// queries in flight; it fails at once when either is reached.
func (d *DoT) Exchange(ctx context.Context, q *dns.Msg) (*dns.Msg, error) {
	select {
	case d.slots <- struct{}{}:
	default:
		return nil, errBusy
	}
	defer func() { <-d.slots }()
	d.mu.Lock()
	ok := d.budget.Take(1, d.now())
	d.mu.Unlock()
	if !ok {
		return nil, errBudget
	}
	return d.exchange(ctx, q)
}

// exchange sends q on an idle connection or a new one. A reused
// connection that fails is replaced once by a new one.
func (d *DoT) exchange(ctx context.Context, q *dns.Msg) (*dns.Msg, error) {
	ctx, cancel := context.WithTimeout(ctx, d.timeout)
	defer cancel()
	co := d.take()
	if co != nil {
		r, err := d.roundTrip(ctx, co, q)
		if err == nil {
			d.put(co)
			return r, nil
		}
		co.Close()
		if ctx.Err() != nil || errors.Is(err, errMismatch) {
			return nil, err
		}
	}
	co, err := d.dial(ctx)
	if err != nil {
		return nil, err
	}
	r, err := d.roundTrip(ctx, co, q)
	if err != nil {
		co.Close()
		return nil, err
	}
	d.put(co)
	return r, nil
}

func (d *DoT) roundTrip(ctx context.Context, co *dns.Conn, q *dns.Msg) (*dns.Msg, error) {
	r, _, err := d.client.ExchangeWithConnContext(ctx, q, co)
	if err != nil {
		return nil, err
	}
	if len(r.Question) != 1 || len(q.Question) != 1 ||
		!strings.EqualFold(r.Question[0].Name, q.Question[0].Name) ||
		r.Question[0].Qtype != q.Question[0].Qtype || r.Question[0].Qclass != q.Question[0].Qclass {
		return nil, errMismatch
	}
	return r, nil
}

func (d *DoT) take() *dns.Conn {
	d.mu.Lock()
	defer d.mu.Unlock()
	n := len(d.idle)
	if n == 0 {
		return nil
	}
	co := d.idle[n-1]
	d.idle = d.idle[:n-1]
	return co
}

func (d *DoT) put(co *dns.Conn) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed || len(d.idle) >= maxIdle {
		co.Close()
		return
	}
	d.idle = append(d.idle, co)
}

// probeOnce asks for quad9.net. A outside the query budget; only an
// answer with RCODE NOERROR counts.
func (d *DoT) probeOnce(ctx context.Context) error {
	q := new(dns.Msg)
	q.SetQuestion("quad9.net.", dns.TypeA)
	q.SetEdns0(udpEDNS, false)
	r, err := d.exchange(ctx, q)
	if err != nil {
		return err
	}
	if r.Rcode != dns.RcodeSuccess {
		return fmt.Errorf("dnspot: probe answered %s", dns.RcodeToString[r.Rcode])
	}
	return nil
}

// check runs one probe: a good one makes the upstream healthy, the third
// failed one in a row makes it unhealthy. A change is handed to Report.
func (d *DoT) check(ctx context.Context) {
	err := d.probe(ctx)
	d.mu.Lock()
	var state int8
	if err == nil {
		d.fails = 0
		d.healthy.Store(true)
		state = 1
	} else if d.fails++; d.fails >= probeFails {
		d.healthy.Store(false)
		state = -1
	}
	changed := state != 0 && state != d.state
	if changed {
		d.state = state
	}
	d.mu.Unlock()
	if changed && d.Report != nil {
		d.Report(state == 1, err)
	}
}

// wait is the time until the next probe.
func (d *DoT) wait() time.Duration {
	if d.Healthy() {
		return d.interval
	}
	return d.retry
}

// Run probes at once and then every 60 s while healthy and every 10 s
// while not, until ctx ends; then it closes the idle connections.
func (d *DoT) Run(ctx context.Context) {
	defer func() {
		d.mu.Lock()
		d.closed = true
		for _, co := range d.idle {
			co.Close()
		}
		d.idle = nil
		d.mu.Unlock()
	}()
	d.check(ctx)
	t := time.NewTimer(d.wait())
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			d.check(ctx)
			t.Reset(d.wait())
		}
	}
}
