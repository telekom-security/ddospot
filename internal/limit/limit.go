// Package limit keeps the response budgets of the pots (per source and
// protocol, per network and in total) and classifies sources as scanners
// or targets.
package limit

import (
	"net/netip"
	"sync"
	"time"

	"github.com/t3chn0m4g3/ddospot/internal/bucket"
)

// Proto names a pot.
type Proto string

const (
	Chargen Proto = "chargen"
	DNS     Proto = "dns"
	NTP     Proto = "ntp"
	SSDP    Proto = "ssdp"
)

const maxSampleReq = 512

// Config holds the budgets and time spans of a Limiter.
type Config struct {
	PerSource, PerNet    int
	Window, Classify     time.Duration
	GlobalPPS, GlobalBPS float64
	MaxSources, MaxNets  int
}

// Defaults returns the standard budgets with the given classification hold.
func Defaults(classify time.Duration) Config {
	return Config{PerSource: 5, PerNet: 20, Window: 10 * time.Minute, Classify: classify,
		GlobalPPS: 50, GlobalBPS: 65536, MaxSources: 200000, MaxNets: 200000}
}

// Sample is the first packet of a source, kept for its log event.
type Sample struct {
	Transport string // "udp" | "tcp"
	Req       []byte // raw request; copied, at most 512 bytes are kept
	ReqSize   int    // set by the limiter: length of the request before cutting
	RespSize  int
	Fields    map[string]any // pot fields: dns_name, mode, st, mx, ...
}

// Source is the state of one address on one protocol.
type Source struct {
	Proto       Proto
	Addr        netip.Addr
	Port        uint16
	First, Last time.Time
	Packets     uint64
	Sample      Sample
}

// Net is the state of one /24 (IPv4) or /48 (IPv6) network.
type Net struct {
	Prefix      netip.Prefix
	First, Last time.Time
	Packets     uint64
	Sources     int
}

// Observer receives the classification events. Calls happen outside the
// limiter's lock.
type Observer interface {
	Scanner(Source)
	TargetStart(Source)
	TargetEnd(Source)
	NetStart(Net)
	NetEnd(Net)
}

type class uint8

const (
	pending class = iota
	scanner
	target
)

type netEntry struct {
	Net
	blocked  bool
	answered int
}

type srcEntry struct {
	Source
	class    class
	answered int
	net      *netEntry
}

type srcKey struct {
	proto Proto
	addr  netip.Addr
}

// Limiter is safe for concurrent use.
type Limiter struct {
	cfg  Config
	now  func() time.Time
	obs  Observer
	mu   sync.Mutex
	srcs map[srcKey]*srcEntry
	nets map[netip.Prefix]*netEntry
	pkts *bucket.Bucket
	byts *bucket.Bucket
}

// New returns a Limiter reading time from now and reporting to obs.
func New(cfg Config, now func() time.Time, obs Observer) *Limiter {
	return &Limiter{
		cfg:  cfg,
		now:  now,
		obs:  obs,
		srcs: make(map[srcKey]*srcEntry),
		nets: make(map[netip.Prefix]*netEntry),
		pkts: bucket.New(cfg.GlobalPPS, cfg.GlobalPPS),
		byts: bucket.New(cfg.GlobalBPS, cfg.GlobalBPS),
	}
}

func netOf(a netip.Addr) netip.Prefix {
	bits := 48
	if a.Is4() {
		bits = 24
	}
	return netip.PrefixFrom(a, bits).Masked()
}

func cloneSample(s Sample) Sample {
	s.ReqSize = len(s.Req)
	if len(s.Req) > maxSampleReq {
		s.Req = s.Req[:maxSampleReq]
	}
	s.Req = append([]byte(nil), s.Req...)
	return s
}

// Admit counts the packet and reports whether an answer of the given size may be sent.
func (l *Limiter) Admit(p Proto, src netip.AddrPort, s Sample, datagrams, bytes int) bool {
	addr := src.Addr().Unmap()
	var calls []func()
	ok := func() bool {
		l.mu.Lock()
		defer l.mu.Unlock()
		now := l.now()

		prefix := netOf(addr)
		n := l.nets[prefix]
		if n == nil {
			if len(l.nets) >= l.cfg.MaxNets {
				return false
			}
			n = &netEntry{Net: Net{Prefix: prefix, First: now}}
			l.nets[prefix] = n
		}
		key := srcKey{p, addr}
		e := l.srcs[key]
		if e == nil {
			if len(l.srcs) >= l.cfg.MaxSources {
				return false
			}
			e = &srcEntry{
				Source: Source{Proto: p, Addr: addr, Port: src.Port(), First: now, Sample: cloneSample(s)},
				class:  pending,
				net:    n,
			}
			l.srcs[key] = e
			n.Sources++
		}
		e.Last = now
		e.Packets++
		n.Last = now
		n.Packets++

		if n.blocked {
			return false
		}
		if e.answered >= l.cfg.PerSource {
			if e.class != target {
				e.class = target
				snap := e.Source
				calls = append(calls, func() { l.obs.TargetStart(snap) })
			}
			return false
		}
		if n.answered >= l.cfg.PerNet {
			n.blocked = true
			snap := n.Net
			calls = append(calls, func() { l.obs.NetStart(snap) })
			return false
		}
		if l.pkts.Can(float64(datagrams), now) && l.byts.Can(float64(bytes), now) {
			l.pkts.Take(float64(datagrams), now)
			l.byts.Take(float64(bytes), now)
		} else {
			return false
		}
		e.answered++
		n.answered++
		return true
	}()
	for _, c := range calls {
		c()
	}
	return ok
}

// Tick classifies and expires; it is called once a second.
func (l *Limiter) Tick() {
	l.mu.Lock()
	now := l.now()
	var calls []func()
	for k, e := range l.srcs {
		if e.class == pending && now.Sub(e.First) >= l.cfg.Classify {
			e.class = scanner
			if !e.net.blocked {
				snap := e.Source
				calls = append(calls, func() { l.obs.Scanner(snap) })
			}
		}
		if now.Sub(e.Last) >= l.cfg.Window {
			if e.class == target && !e.net.blocked {
				snap := e.Source
				calls = append(calls, func() { l.obs.TargetEnd(snap) })
			}
			delete(l.srcs, k)
		}
	}
	for k, n := range l.nets {
		if now.Sub(n.Last) >= l.cfg.Window {
			if n.blocked {
				snap := n.Net
				calls = append(calls, func() { l.obs.NetEnd(snap) })
			}
			delete(l.nets, k)
		}
	}
	l.mu.Unlock()
	for _, c := range calls {
		c()
	}
}

// Flush emits every open state and clears the tables; it is called on shutdown.
func (l *Limiter) Flush() {
	l.mu.Lock()
	var calls []func()
	for _, e := range l.srcs {
		if e.net.blocked {
			continue
		}
		snap := e.Source
		switch e.class {
		case pending:
			calls = append(calls, func() { l.obs.Scanner(snap) })
		case target:
			calls = append(calls, func() { l.obs.TargetEnd(snap) })
		}
	}
	for _, n := range l.nets {
		if n.blocked {
			snap := n.Net
			calls = append(calls, func() { l.obs.NetEnd(snap) })
		}
	}
	l.srcs = make(map[srcKey]*srcEntry)
	l.nets = make(map[netip.Prefix]*netEntry)
	l.mu.Unlock()
	for _, c := range calls {
		c()
	}
}
