// Package app wires the pots, the limiter and the logs together and runs
// them until the context ends.
package app

import (
	"context"
	crand "crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/telekom-security/ddospot/internal/chargen"
	dnspot "github.com/telekom-security/ddospot/internal/dns"
	"github.com/telekom-security/ddospot/internal/events"
	"github.com/telekom-security/ddospot/internal/jsonlog"
	"github.com/telekom-security/ddospot/internal/limit"
	"github.com/telekom-security/ddospot/internal/ntp"
	"github.com/telekom-security/ddospot/internal/persona"
	"github.com/telekom-security/ddospot/internal/ssdp"
)

// Version is the version of the program.
const Version = "2.0.0"

const (
	tickEvery   = time.Second
	reportEvery = time.Minute

	udpSize         = 4096 // read buffer of the DNS server on UDP
	tcpReadTimeout  = 5 * time.Second
	tcpQueries      = 64  // queries per TCP connection
	tcpConns        = 256 // open TCP connections of DNS
	tcpConnsPerAddr = 4   // open TCP connections of DNS per address

	dnsStop  = time.Second             // bound for the stop of the DNS servers
	stopTime = 1500 * time.Millisecond // bound for the whole stop
)

// stdout receives the status lines; tests replace it.
var stdout io.Writer = os.Stdout

// Addrs holds the bound addresses of the pots; DNS is the same for UDP and
// TCP.
type Addrs struct{ Chargen, DNS, NTP, SSDP string }

// Run starts the pots and serves until ctx ends, then stops them, writes
// the open events and closes the logs. With recursion on and up nil it
// resolves through Quad9 over DNS over TLS. A listen error is returned at
// once.
func Run(ctx context.Context, cfg Config, up dnspot.Upstream) error {
	return runWithAddrs(ctx, cfg, up, nil)
}

// rollPersona rolls the persona with a seed from crypto/rand.
func rollPersona() persona.Persona {
	var seed [8]byte
	crand.Read(seed[:])
	return persona.Roll(rand.New(rand.NewSource(int64(binary.LittleEndian.Uint64(seed[:])))))
}

type listeners struct {
	chargen, dns, ntp, ssdp *net.UDPConn
	tcp                     net.Listener
}

func (l *listeners) close() {
	for _, c := range []*net.UDPConn{l.chargen, l.dns, l.ntp, l.ssdp} {
		if c != nil {
			c.Close()
		}
	}
	if l.tcp != nil {
		l.tcp.Close()
	}
}

// listen opens the four UDP sockets and the TCP socket of DNS, which takes
// the port of the DNS UDP socket. On an error the sockets opened so far are
// closed again.
func listen(cfg Config) (*listeners, error) {
	ls := &listeners{}
	var err error
	udp := func(addr string) *net.UDPConn {
		if err != nil {
			return nil
		}
		var pc net.PacketConn
		if pc, err = net.ListenPacket("udp", addr); err != nil {
			return nil
		}
		return pc.(*net.UDPConn)
	}
	ls.chargen = udp(cfg.Chargen)
	ls.dns = udp(cfg.DNS)
	ls.ntp = udp(cfg.NTP)
	ls.ssdp = udp(cfg.SSDP)
	if err == nil {
		ls.tcp, err = net.Listen("tcp", tcpAddr(cfg.DNS, ls.dns))
	}
	if err != nil {
		ls.close()
		return nil, err
	}
	return ls, nil
}

func tcpAddr(addr string, udp *net.UDPConn) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return net.JoinHostPort(host, strconv.Itoa(udp.LocalAddr().(*net.UDPAddr).Port))
}

// newDNSServers returns the DNS servers for UDP and TCP. Both hand every
// message that parses to h, so that all answers stay within the budgets.
// The TCP server keeps at most tcpConns connections open, tcpConnsPerAddr
// of them from one address.
func newDNSServers(h dns.Handler, pc net.PacketConn, l net.Listener, started func()) (udp, tcp *dns.Server) {
	udp = &dns.Server{PacketConn: pc, Handler: h, UDPSize: udpSize,
		MsgAcceptFunc: dnspot.Accept, DecorateReader: dnspot.StrictReader, NotifyStartedFunc: started}
	tcp = &dns.Server{Listener: dnspot.LimitListener(l, tcpConns, tcpConnsPerAddr), Handler: h, ReadTimeout: tcpReadTimeout, MaxTCPQueries: tcpQueries,
		MsgAcceptFunc: dnspot.Accept, DecorateReader: dnspot.StrictReader, NotifyStartedFunc: started}
	return udp, tcp
}

// report prints the lines the log budget left out and the lines lost to
// errors since the last call, each only when there were any.
func report(out io.Writer, w *jsonlog.Writer) {
	if n := w.Dropped(); n > 0 {
		fmt.Fprintf(out, "log lines dropped: %d\n", n)
	}
	if n := w.Errors(); n > 0 {
		fmt.Fprintf(out, "log write errors: %d\n", n)
	}
}

// reportUpstream prints a change of the health of the DNS upstream.
func reportUpstream(out io.Writer, ok bool, err error) {
	if ok {
		fmt.Fprintln(out, "dns upstream: answering, class IN resolved")
		return
	}
	fmt.Fprintf(out, "dns upstream: not answering (%v), class IN answered with REFUSED\n", err)
}

// every calls f each interval until stop is closed.
func every(interval time.Duration, stop <-chan struct{}, f func()) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			f()
		}
	}
}

// waitUntil waits for wg until the deadline and reports whether it ended.
func waitUntil(wg *sync.WaitGroup, by time.Time) bool {
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	t := time.NewTimer(time.Until(by))
	defer t.Stop()
	select {
	case <-done:
		return true
	case <-t.C:
		return false
	}
}

func runWithAddrs(ctx context.Context, cfg Config, up dnspot.Upstream, addrs chan<- Addrs) error {
	p := rollPersona()
	fmt.Fprintf(stdout, "ddospot v%s persona=%s\n", Version, p.ID)

	jl, err := jsonlog.Open(cfg.LogDir, time.Now)
	if err != nil {
		return err
	}
	lim := limit.New(limit.Defaults(cfg.Classify), time.Now, events.New(jl, p.ID))

	ls, err := listen(cfg)
	if err != nil {
		jl.Close()
		return err
	}

	var dot *dnspot.DoT
	switch {
	case !cfg.Recursion:
		up = nil
	case up == nil:
		dot = dnspot.NewDoT(time.Now)
		dot.Report = func(ok bool, err error) { reportUpstream(stdout, ok, err) }
		up = dot
	}

	// The UDP pots.
	cg := chargen.New(ls.chargen, lim)
	nt := ntp.New(ls.ntp, lim, &p)
	sd := ssdp.New(ls.ssdp, lim, &p)
	var pots sync.WaitGroup
	for _, serve := range []func() error{cg.Serve, nt.Serve, sd.Serve} {
		pots.Go(func() { serve() })
	}

	// DNS on UDP and TCP.
	started := make(chan struct{}, 2)
	du, dt := newDNSServers(dnspot.NewHandler(&p, lim, up), ls.dns, ls.tcp, func() { started <- struct{}{} })
	dnsErr := make(chan error, 2)
	var dnsServing sync.WaitGroup
	for _, s := range []*dns.Server{du, dt} {
		dnsServing.Go(func() {
			if err := s.ActivateAndServe(); err != nil {
				dnsErr <- err
			}
		})
	}
	var runErr error
	for n := 0; n < 2 && runErr == nil; {
		select {
		case <-started:
			n++
		case runErr = <-dnsErr:
		}
	}

	// Classification, the log report and the upstream probes.
	stopTickers := make(chan struct{})
	var tickers sync.WaitGroup
	tickers.Go(func() { every(tickEvery, stopTickers, lim.Tick) })
	tickers.Go(func() { every(reportEvery, stopTickers, func() { report(stdout, jl) }) })
	dotCtx, dotCancel := context.WithCancel(context.Background())
	var dotRun sync.WaitGroup
	if dot != nil {
		dotRun.Go(func() { dot.Run(dotCtx) })
	}

	if runErr == nil {
		if addrs != nil {
			select {
			case addrs <- Addrs{
				Chargen: ls.chargen.LocalAddr().String(),
				DNS:     ls.dns.LocalAddr().String(),
				NTP:     ls.ntp.LocalAddr().String(),
				SSDP:    ls.ssdp.LocalAddr().String(),
			}:
			case <-ctx.Done():
			}
		}
		select {
		case <-ctx.Done():
		case runErr = <-dnsErr:
		}
	}

	// Stop.
	by := time.Now().Add(stopTime)
	for _, c := range []*net.UDPConn{ls.chargen, ls.ntp, ls.ssdp} {
		c.Close()
	}
	pots.Wait()
	sd.Close()

	sctx, scancel := context.WithTimeout(context.Background(), dnsStop)
	var stops sync.WaitGroup
	for _, s := range []*dns.Server{du, dt} {
		stops.Go(func() { s.ShutdownContext(sctx) })
	}
	stops.Wait()
	scancel()
	ls.dns.Close()
	ls.tcp.Close()
	waitUntil(&dnsServing, by)

	dotCancel()
	waitUntil(&dotRun, by)
	close(stopTickers)
	tickers.Wait()

	lim.Flush()
	jl.Close()
	report(stdout, jl)
	return runErr
}
