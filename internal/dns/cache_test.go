package dnspot

import (
	"testing"
	"time"

	"github.com/miekg/dns"
)

func aRR(name string, ttl uint32) dns.RR {
	return &dns.A{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl}, A: []byte{192, 0, 2, 7}}
}

func soaRR(ttl, minttl uint32) dns.RR {
	return &dns.SOA{Hdr: dns.RR_Header{Name: "example.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: ttl}, Ns: "ns.example.", Mbox: "h.example.", Minttl: minttl}
}

func reply(rcode int, ans, ns []dns.RR) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion("x.example.", dns.TypeA)
	m.Response = true
	m.Rcode = rcode
	m.Answer, m.Ns = ans, ns
	return m
}

func TestEntryTTL(t *testing.T) {
	cases := []struct {
		name string
		m    *dns.Msg
		ttl  uint32
	}{
		{"answer", reply(dns.RcodeSuccess, []dns.RR{aRR("x.example.", 300), aRR("x.example.", 120)}, nil), 120},
		{"answer cap", reply(dns.RcodeSuccess, []dns.RR{aRR("x.example.", 86400)}, nil), 3600},
		{"answer zero", reply(dns.RcodeSuccess, []dns.RR{aRR("x.example.", 0)}, nil), 0},
		{"nxdomain minimum", reply(dns.RcodeNameError, nil, []dns.RR{soaRR(3600, 300)}), 300},
		{"nxdomain soa ttl", reply(dns.RcodeNameError, nil, []dns.RR{soaRR(60, 300)}), 60},
		{"nxdomain cap", reply(dns.RcodeNameError, nil, []dns.RR{soaRR(86400, 86400)}), 900},
		{"nodata", reply(dns.RcodeSuccess, nil, []dns.RR{soaRR(7200, 7200)}), 900},
		{"nodata without soa", reply(dns.RcodeSuccess, nil, nil), 0},
		{"servfail", reply(dns.RcodeServerFailure, nil, nil), 0},
		{"refused", reply(dns.RcodeRefused, nil, []dns.RR{soaRR(300, 300)}), 0},
	}
	for _, c := range cases {
		e, ttl := entryOf(c.m)
		if ttl != c.ttl || e.rcode != c.m.Rcode {
			t.Fatalf("%s: ttl %d rcode %d, want %d", c.name, ttl, e.rcode, c.ttl)
		}
		for _, rr := range append(e.answer, e.ns...) {
			if rr.Header().Ttl > 3600 {
				t.Fatalf("%s: record ttl %d", c.name, rr.Header().Ttl)
			}
		}
	}
	e, _ := entryOf(reply(dns.RcodeNameError, nil, []dns.RR{soaRR(3600, 300), aRR("ns.example.", 300)}))
	if len(e.ns) != 1 || e.ns[0].Header().Ttl != 300 || e.ns[0].Header().Rrtype != dns.TypeSOA {
		t.Fatalf("negative authority %v", e.ns)
	}
	e, _ = entryOf(reply(dns.RcodeSuccess, []dns.RR{aRR("x.example.", 300)}, []dns.RR{soaRR(300, 300)}))
	if len(e.ns) != 0 {
		t.Fatalf("authority of an answer %v", e.ns)
	}
}

func TestCacheCountsDownAndExpires(t *testing.T) {
	c := newCache(10)
	k := keyOf(dns.Question{Name: "X.Example.", Qtype: dns.TypeA, Qclass: dns.ClassINET})
	e, ttl := entryOf(reply(dns.RcodeSuccess, []dns.RR{aRR("x.example.", 100), aRR("x.example.", 300)}, nil))
	c.put(k, e, ttl, now)
	got, ok := c.get(keyOf(dns.Question{Name: "x.EXAMPLE.", Qtype: dns.TypeA, Qclass: dns.ClassINET}), now.Add(30*time.Second))
	if !ok || got.answer[0].Header().Ttl != 70 || got.answer[1].Header().Ttl != 270 {
		t.Fatalf("%v %v", ok, got.answer)
	}
	got.answer[0].Header().Ttl = 9999
	if got, _ := c.get(k, now); got.answer[0].Header().Ttl != 100 {
		t.Fatal("get hands out the stored records")
	}
	e.answer[1].Header().Ttl = 9999
	if got, _ := c.get(k, now); got.answer[1].Header().Ttl != 300 {
		t.Fatal("put keeps the caller's records")
	}
	if _, ok := c.get(k, now.Add(100*time.Second)); ok {
		t.Fatal("expired entry returned")
	}
	if len(c.m) != 0 || c.order.Len() != 0 {
		t.Fatal("expired entry kept")
	}
	if _, ok := c.get(keyOf(dns.Question{Name: "x.example.", Qtype: dns.TypeAAAA, Qclass: dns.ClassINET}), now); ok {
		t.Fatal("other type")
	}
}

func TestCacheZeroTTLNotStored(t *testing.T) {
	c := newCache(10)
	k := cacheKey{"x.example.", dns.TypeA, dns.ClassINET}
	c.put(k, entry{}, 0, now)
	if _, ok := c.get(k, now); ok {
		t.Fatal()
	}
}

func TestCacheDropsOldestFirst(t *testing.T) {
	c := newCache(3)
	e, ttl := entryOf(reply(dns.RcodeSuccess, []dns.RR{aRR("x.example.", 300)}, nil))
	key := func(n string) cacheKey { return cacheKey{n + ".example.", dns.TypeA, dns.ClassINET} }
	for i, n := range []string{"a", "b", "c"} {
		c.put(key(n), e, ttl, now.Add(time.Duration(i)*time.Second))
	}
	c.put(key("a"), e, ttl, now.Add(5*time.Second)) // stored again: now the newest
	c.put(key("d"), e, ttl, now.Add(6*time.Second))
	if len(c.m) != 3 {
		t.Fatalf("entries %d", len(c.m))
	}
	for n, want := range map[string]bool{"a": true, "b": false, "c": true, "d": true} {
		if _, ok := c.get(key(n), now.Add(7*time.Second)); ok != want {
			t.Fatalf("%s: %v", n, ok)
		}
	}
	if maxEntries != 10000 {
		t.Fatalf("max entries %d", maxEntries)
	}
}

func TestCacheClockBack(t *testing.T) {
	c := newCache(3)
	e, ttl := entryOf(reply(dns.RcodeSuccess, []dns.RR{aRR("x.example.", 300)}, nil))
	k := cacheKey{"x.example.", dns.TypeA, dns.ClassINET}
	c.put(k, e, ttl, now)
	got, ok := c.get(k, now.Add(-time.Minute))
	if !ok || got.answer[0].Header().Ttl != 300 {
		t.Fatalf("%v %v", ok, got.answer)
	}
}
