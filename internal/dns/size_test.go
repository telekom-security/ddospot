package dnspot

import (
	"strings"
	"testing"

	"github.com/miekg/dns"
)

func bigReply(req *dns.Msg, n int) *dns.Msg {
	m := new(dns.Msg)
	m.SetReply(req)
	for i := 0; i < n; i++ {
		m.Answer = append(m.Answer, &dns.TXT{Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 300}, Txt: []string{strings.Repeat("a", 200)}})
	}
	m.Ns = []dns.RR{aRR("ns.example.", 300)}
	m.Extra = []dns.RR{aRR("ns.example.", 300)}
	if req.IsEdns0() != nil {
		m.SetEdns0(1232, false)
	}
	return m
}

func TestLimitSizes(t *testing.T) {
	cases := []struct {
		name  string
		edns  uint16 // 0 = no OPT
		udp   bool
		limit int
	}{
		{"udp", 0, true, 512},
		{"udp edns 4096", 4096, true, 1232},
		{"udp edns 1400", 1400, true, 1232},
		{"udp edns 800", 800, true, 800},
		{"udp edns 100", 100, true, 512},
		{"tcp", 0, false, 65535},
		{"tcp edns", 1232, false, 65535},
	}
	for _, c := range cases {
		req := new(dns.Msg)
		req.SetQuestion("big.example.", dns.TypeTXT)
		if c.edns != 0 {
			req.SetEdns0(c.edns, false)
		}
		if got := maxSize(req, c.udp); got != c.limit {
			t.Fatalf("%s: limit %d, want %d", c.name, got, c.limit)
		}
		for _, n := range []int{1, 2, 3, 5, 20} {
			resp := Limit(bigReply(req, n), req, c.udp)
			fits := bigReply(req, n)
			fits.Compress = true
			b, err := resp.Pack()
			if err != nil || len(b) > c.limit {
				t.Fatalf("%s/%d: %d bytes, %v", c.name, n, len(b), err)
			}
			fb, _ := fits.Pack()
			if len(fb) <= c.limit {
				if resp.Truncated || len(resp.Answer) != n {
					t.Fatalf("%s/%d: cut although it fits", c.name, n)
				}
				continue
			}
			if !resp.Truncated || len(resp.Answer) != 0 || len(resp.Ns) != 0 {
				t.Fatalf("%s/%d: tc=%v answers=%d ns=%d", c.name, n, resp.Truncated, len(resp.Answer), len(resp.Ns))
			}
			if (req.IsEdns0() != nil) != (len(resp.Extra) == 1 && resp.IsEdns0() != nil) {
				t.Fatalf("%s/%d: extra %v", c.name, n, resp.Extra)
			}
			if len(resp.Question) != 1 {
				t.Fatalf("%s/%d: question dropped", c.name, n)
			}
		}
	}
}

// An answer just above or just below a limit is cut by its packed size.
func TestLimitAtTheEdge(t *testing.T) {
	req := new(dns.Msg)
	req.SetQuestion("edge.example.", dns.TypeTXT)
	for n := 400; n <= 520; n++ {
		resp := new(dns.Msg)
		resp.SetReply(req)
		txt := strings.Repeat("a", n)
		resp.Answer = []dns.RR{&dns.TXT{Hdr: dns.RR_Header{Name: "edge.example.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 300}, Txt: []string{txt[:n/3], txt[n/3 : 2*n/3], txt[2*n/3:]}}}
		full := resp.Copy()
		full.Compress = true
		fb, err := full.Pack()
		if err != nil {
			t.Fatal(err)
		}
		b, err := Limit(resp, req, true).Pack()
		if err != nil || len(b) > 512 {
			t.Fatalf("%d: %d bytes, %v", n, len(b), err)
		}
		if cut := resp.Truncated; cut != (len(fb) > 512) {
			t.Fatalf("%d: packed %d, truncated %v", n, len(fb), cut)
		}
	}
}
