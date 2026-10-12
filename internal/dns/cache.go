package dnspot

import (
	"container/list"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

const (
	maxEntries    = 10000
	maxEntryBytes = 4096     // larger entries are not cached
	maxBytes      = 16 << 20 // all entries together
	maxTTL        = 3600     // seconds, answers
	maxNegTTL     = 900      // seconds, NXDOMAIN and NODATA
)

// cacheKey is a question with its name in lower case.
type cacheKey struct {
	name          string
	qtype, qclass uint16
}

func keyOf(q dns.Question) cacheKey {
	return cacheKey{strings.ToLower(q.Name), q.Qtype, q.Qclass}
}

// entry is what an answer takes from the upstream reply: the RCODE, the
// answer section and, for NXDOMAIN and NODATA, the SOA record.
type entry struct {
	rcode  int
	answer []dns.RR
	ns     []dns.RR
}

// size is the length of the records of e in uncompressed wire format,
// at least their packed length.
func size(e entry) int {
	n := 0
	for _, rr := range e.answer {
		n += dns.Len(rr)
	}
	for _, rr := range e.ns {
		n += dns.Len(rr)
	}
	return n
}

// aliasesOnly reports whether the answer section holds only CNAME and
// DNAME records for a question of another type: the name leads to a
// NODATA answer.
func aliasesOnly(m *dns.Msg, answer []dns.RR) bool {
	if len(answer) == 0 || len(m.Question) != 1 {
		return false
	}
	switch m.Question[0].Qtype {
	case dns.TypeCNAME, dns.TypeDNAME:
		return false
	}
	for _, rr := range answer {
		switch rr.Header().Rrtype {
		case dns.TypeCNAME, dns.TypeDNAME:
		default:
			return false
		}
	}
	return true
}

// entryOf takes the parts of an upstream reply that go into an answer,
// as copies with their TTLs capped, and the time the entry may be
// cached in seconds (0 = not cached). Answers are cached for their
// lowest record TTL, at most 3600 s; NXDOMAIN and NODATA, also behind
// CNAME or DNAME records, for the lower of the SOA TTL and the SOA
// minimum, at most 900 s. Other RCODEs and negative replies without a
// SOA record are not cached.
func entryOf(m *dns.Msg) (entry, uint32) {
	e := entry{rcode: m.Rcode}
	ttl := uint32(maxTTL)
	for _, rr := range m.Answer {
		if rr.Header().Rrtype == dns.TypeOPT {
			continue
		}
		c := dns.Copy(rr)
		h := c.Header()
		h.Ttl = min(h.Ttl, maxTTL)
		ttl = min(ttl, h.Ttl)
		e.answer = append(e.answer, c)
	}
	negative := m.Rcode == dns.RcodeNameError ||
		m.Rcode == dns.RcodeSuccess && (len(e.answer) == 0 || aliasesOnly(m, e.answer))
	if !negative {
		if m.Rcode != dns.RcodeSuccess {
			return e, 0
		}
		return e, ttl
	}
	for _, rr := range m.Ns {
		soa, ok := rr.(*dns.SOA)
		if !ok {
			continue
		}
		neg := min(soa.Hdr.Ttl, soa.Minttl, maxNegTTL)
		c := dns.Copy(soa)
		c.Header().Ttl = neg
		e.ns = []dns.RR{c}
		return e, min(ttl, neg)
	}
	return e, 0
}

type slot struct {
	key             cacheKey
	e               entry
	size            int
	stored, expires time.Time
}

// cache holds up to max entries of together at most maxBytes; when it
// is full, the entries stored first are dropped.
type cache struct {
	mu       sync.Mutex
	max      int
	maxBytes int
	bytes    int // size of all entries
	m        map[cacheKey]*list.Element
	order    *list.List // of *slot, oldest first
}

func newCache(max, maxBytes int) *cache {
	return &cache{max: max, maxBytes: maxBytes, m: make(map[cacheKey]*list.Element), order: list.New()}
}

// remove drops one entry; the caller holds c.mu.
func (c *cache) remove(el *list.Element) {
	s := el.Value.(*slot)
	c.order.Remove(el)
	delete(c.m, s.key)
	c.bytes -= s.size
}

// aged returns copies of rrs with age seconds taken off their TTLs.
func aged(rrs []dns.RR, age uint32) []dns.RR {
	if rrs == nil {
		return nil
	}
	out := make([]dns.RR, len(rrs))
	for i, rr := range rrs {
		c := dns.Copy(rr)
		h := c.Header()
		h.Ttl -= min(h.Ttl, age)
		out[i] = c
	}
	return out
}

// get returns copies of the records of k with their TTLs counted down.
func (c *cache) get(k cacheKey, now time.Time) (entry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	el := c.m[k]
	if el == nil {
		return entry{}, false
	}
	s := el.Value.(*slot)
	if !now.Before(s.expires) {
		c.remove(el)
		return entry{}, false
	}
	var age uint32
	if d := now.Sub(s.stored); d > 0 {
		age = uint32(d / time.Second)
	}
	return entry{rcode: s.e.rcode, answer: aged(s.e.answer, age), ns: aged(s.e.ns, age)}, true
}

// put stores copies of the records of e under k for ttl seconds. An
// entry over maxEntryBytes is not stored.
func (c *cache) put(k cacheKey, e entry, ttl uint32, now time.Time) {
	n := size(e)
	if ttl == 0 || n > maxEntryBytes || n > c.maxBytes {
		return
	}
	s := &slot{
		key:     k,
		e:       entry{rcode: e.rcode, answer: aged(e.answer, 0), ns: aged(e.ns, 0)},
		size:    n,
		stored:  now,
		expires: now.Add(time.Duration(ttl) * time.Second),
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if el := c.m[k]; el != nil {
		c.remove(el)
	}
	for len(c.m) >= c.max || c.bytes+n > c.maxBytes {
		c.remove(c.order.Front())
	}
	c.m[k] = c.order.PushBack(s)
	c.bytes += n
}
