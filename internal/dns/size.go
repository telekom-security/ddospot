package dnspot

import "github.com/miekg/dns"

const (
	udpPlain = 512   // UDP answer without EDNS
	udpEDNS  = 1232  // UDP answer with EDNS, at most
	tcpMax   = 65535 // TCP answer
)

// maxSize is the largest answer to req on the given transport.
func maxSize(req *dns.Msg, udp bool) int {
	if !udp {
		return tcpMax
	}
	if o := req.IsEdns0(); o != nil {
		return max(udpPlain, min(int(o.UDPSize()), udpEDNS))
	}
	return udpPlain
}

// packedLen is the length of m as WriteMsg sends it; a message that
// does not pack counts as larger than any answer.
func packedLen(m *dns.Msg) int {
	b, err := m.Pack()
	if err != nil {
		return tcpMax + 1
	}
	return len(b)
}

// Limit fits resp to the answer size of req on its transport: UDP 512
// bytes without EDNS, the client's EDNS size within 512 to 1232 bytes
// with it, TCP 65535 bytes, measured on the packed message. An answer
// that does not fit keeps its header, question and OPT record, gets TC=1
// and loses every other record. Limit turns on name compression, which
// WriteMsg then uses as well.
func Limit(resp *dns.Msg, req *dns.Msg, udp bool) *dns.Msg {
	resp.Compress = true
	if packedLen(resp) <= maxSize(req, udp) {
		return resp
	}
	resp.Truncated = true
	resp.Answer, resp.Ns = nil, nil
	var extra []dns.RR
	for _, rr := range resp.Extra {
		if rr.Header().Rrtype == dns.TypeOPT {
			extra = append(extra, rr)
		}
	}
	resp.Extra = extra
	return resp
}
