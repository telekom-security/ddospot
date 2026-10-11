// Package limit keeps the response budgets of the pots (per source and
// protocol, per network and in total) and classifies sources as scanners
// or targets.
package limit

import (
	"container/list"
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

// Config holds the budgets and time spans of a Limiter. MaxSources and
// MaxNets cap the tables of UDP sources and of networks, MaxTCPSources the
// table of DNS over TCP sources.
type Config struct {
	PerSource, PerNet    int
	Window, Classify     time.Duration
	GlobalPPS, GlobalBPS float64
	MaxSources, MaxNets  int
	MaxTCPSources        int
}

// Defaults returns the standard budgets with the given classification hold.
func Defaults(classify time.Duration) Config {
	return Config{PerSource: 5, PerNet: 20, Window: 10 * time.Minute, Classify: classify,
		GlobalPPS: 50, GlobalBPS: 65536, MaxSources: 200000, MaxNets: 200000, MaxTCPSources: 20000}
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
	blocked bool
	elem    *list.Element // in Limiter.netQ
}

type srcEntry struct {
	Source
	key       srcKey
	class     class
	announced bool          // TargetStart was emitted, so TargetEnd is owed
	net       *netEntry     // nil for TCP sources
	elem      *list.Element // in Limiter.srcQ
	pend      *list.Element // in Limiter.pendQ while the class is pending
}

type srcKey struct {
	proto Proto
	addr  netip.Addr
	tcp   bool
}

// Limiter is safe for concurrent use.
//
// Every entry also sits in a list ordered by the time Tick looks at: srcQ
// and netQ by Last (an entry moves to the back on each packet), pendQ by
// First. Tick takes entries from the front only while they are due. A
// network is refreshed by every packet of its sources and expires after
// them, so a source's net entry lives at least as long as the source.
type Limiter struct {
	cfg     Config
	now     func() time.Time
	obs     Observer
	mu      sync.Mutex
	srcs    map[srcKey]*srcEntry // UDP sources
	tcpSrcs map[srcKey]*srcEntry // DNS over TCP sources
	nets    map[netip.Prefix]*netEntry
	srcQ    *list.List // *srcEntry, oldest Last first
	pendQ   *list.List // pending *srcEntry, oldest First first
	netQ    *list.List // *netEntry, oldest Last first
	pkts    *bucket.Bucket
	byts    *bucket.Bucket
}

// New returns a Limiter reading time from now and reporting to obs.
func New(cfg Config, now func() time.Time, obs Observer) *Limiter {
	l := &Limiter{
		cfg:  cfg,
		now:  now,
		obs:  obs,
		pkts: bucket.New(cfg.GlobalPPS, cfg.GlobalPPS),
		byts: bucket.New(cfg.GlobalBPS, cfg.GlobalBPS),
	}
	l.reset()
	return l
}

func (l *Limiter) reset() {
	l.srcs = make(map[srcKey]*srcEntry)
	l.tcpSrcs = make(map[srcKey]*srcEntry)
	l.nets = make(map[netip.Prefix]*netEntry)
	l.srcQ, l.pendQ, l.netQ = list.New(), list.New(), list.New()
}

// table returns the source table for the transport and its cap.
func (l *Limiter) table(tcp bool) (map[srcKey]*srcEntry, int) {
	if tcp {
		return l.tcpSrcs, l.cfg.MaxTCPSources
	}
	return l.srcs, l.cfg.MaxSources
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

// Over reports whether the next packet of the source would get no answer
// from Admit for a reason other than the global budget: the source has
// used its budget of the window, its network is blocked or reaches its
// budget with this packet (UDP only), or a table it needs is full. Over
// changes no state; a caller that skips its answer still passes the packet
// to Admit with 0 datagrams and 0 bytes so that it is counted.
func (l *Limiter) Over(p Proto, src netip.AddrPort, tcp bool) bool {
	addr := src.Addr().Unmap()
	l.mu.Lock()
	defer l.mu.Unlock()
	table, capacity := l.table(tcp)
	e := table[srcKey{p, addr, tcp}]
	if e == nil && len(table) >= capacity {
		return true
	}
	if e != nil && e.Packets >= uint64(l.cfg.PerSource) {
		return true
	}
	if tcp {
		return false
	}
	var n *netEntry
	if e != nil {
		n = e.net
	} else if n = l.nets[netOf(addr)]; n == nil {
		return len(l.nets) >= l.cfg.MaxNets
	}
	return n.blocked || n.Packets >= uint64(l.cfg.PerNet)
}

// Admit counts the packet and reports whether an answer of the given size
// may be sent. The source and network budgets count packets: within a
// window the first PerSource packets of a source and the first PerNet
// packets of a network may be answered, as far as the global budget
// allows. The packet after them makes the source a target and blocks the
// network.
//
// A source whose Sample.Transport is "tcp" has a state of its own: it gets
// at most PerSource answers per window, but it is never a target and its
// packets are not counted for its network.
func (l *Limiter) Admit(p Proto, src netip.AddrPort, s Sample, datagrams, bytes int) bool {
	addr := src.Addr().Unmap()
	datagrams, bytes = max(datagrams, 0), max(bytes, 0)
	tcp := s.Transport == "tcp"
	var calls []func()
	ok := func() bool {
		l.mu.Lock()
		defer l.mu.Unlock()
		now := l.now()

		key := srcKey{p, addr, tcp}
		table, capacity := l.table(tcp)
		e := table[key]
		if e == nil {
			if len(table) >= capacity {
				return false
			}
			var n *netEntry
			if !tcp {
				prefix := netOf(addr)
				if n = l.nets[prefix]; n == nil {
					if len(l.nets) >= l.cfg.MaxNets {
						return false
					}
					n = &netEntry{Net: Net{Prefix: prefix, First: now}}
					n.elem = l.netQ.PushBack(n)
					l.nets[prefix] = n
				}
				n.Sources++
			}
			e = &srcEntry{
				Source: Source{Proto: p, Addr: addr, Port: src.Port(), First: now, Sample: cloneSample(s)},
				key:    key,
				class:  pending,
				net:    n,
			}
			e.elem = l.srcQ.PushBack(e)
			e.pend = l.pendQ.PushBack(e)
			table[key] = e
		} else {
			l.srcQ.MoveToBack(e.elem)
		}
		e.Last = now
		e.Packets++
		overSource := e.Packets > uint64(l.cfg.PerSource)
		if tcp {
			return !overSource
		}
		n := e.net
		n.Last = now
		n.Packets++
		l.netQ.MoveToBack(n.elem)

		if n.blocked {
			return false
		}
		if overSource && e.class != target {
			e.class = target
			e.announced = true
			if e.pend != nil {
				l.pendQ.Remove(e.pend)
				e.pend = nil
			}
			snap := e.Source
			calls = append(calls, func() { l.obs.TargetStart(snap) })
		}
		if n.Packets > uint64(l.cfg.PerNet) {
			n.blocked = true
			snap := n.Net
			calls = append(calls, func() { l.obs.NetStart(snap) })
			return false
		}
		if overSource || !l.pkts.Can(float64(datagrams), now) || !l.byts.Can(float64(bytes), now) {
			return false
		}
		l.pkts.Take(float64(datagrams), now)
		l.byts.Take(float64(bytes), now)
		return true
	}()
	for _, c := range calls {
		c()
	}
	return ok
}

// Tick classifies and expires; it is called once a second. It looks only
// at the entries that are due.
func (l *Limiter) Tick() {
	l.mu.Lock()
	now := l.now()
	var calls []func()
	for f := l.pendQ.Front(); f != nil; f = l.pendQ.Front() {
		e := f.Value.(*srcEntry)
		if now.Sub(e.First) < l.cfg.Classify {
			break
		}
		l.pendQ.Remove(f)
		e.pend = nil
		e.class = scanner
		if e.net == nil || !e.net.blocked {
			snap := e.Source
			calls = append(calls, func() { l.obs.Scanner(snap) })
		}
	}
	for f := l.srcQ.Front(); f != nil; f = l.srcQ.Front() {
		e := f.Value.(*srcEntry)
		if now.Sub(e.Last) < l.cfg.Window {
			break
		}
		l.srcQ.Remove(f)
		if e.pend != nil {
			l.pendQ.Remove(e.pend)
			e.pend = nil
		}
		if e.announced {
			snap := e.Source
			calls = append(calls, func() { l.obs.TargetEnd(snap) })
		}
		table, _ := l.table(e.key.tcp)
		delete(table, e.key)
	}
	for f := l.netQ.Front(); f != nil; f = l.netQ.Front() {
		n := f.Value.(*netEntry)
		if now.Sub(n.Last) < l.cfg.Window {
			break
		}
		l.netQ.Remove(f)
		if n.blocked {
			snap := n.Net
			calls = append(calls, func() { l.obs.NetEnd(snap) })
		}
		delete(l.nets, n.Prefix)
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
	for f := l.srcQ.Front(); f != nil; f = f.Next() {
		e := f.Value.(*srcEntry)
		snap := e.Source
		switch {
		case e.announced:
			calls = append(calls, func() { l.obs.TargetEnd(snap) })
		case e.class == pending && (e.net == nil || !e.net.blocked):
			calls = append(calls, func() { l.obs.Scanner(snap) })
		}
	}
	for f := l.netQ.Front(); f != nil; f = f.Next() {
		if n := f.Value.(*netEntry); n.blocked {
			snap := n.Net
			calls = append(calls, func() { l.obs.NetEnd(snap) })
		}
	}
	l.reset()
	l.mu.Unlock()
	for _, c := range calls {
		c()
	}
}
