package ssdp

import (
	"bytes"
	"strings"
)

const (
	maxRead    = 2048
	maxHeaders = 32
	maxMX      = 5

	requestLine = "M-SEARCH * HTTP/1.1\r\n"
	discover    = `"ssdp:discover"`
)

// Request is a parsed M-SEARCH request.
type Request struct {
	ST, MAN, Host string
	MX            int    // 0-5, 0 when HasMX is false
	HasMX         bool   // MX present with a number of at least 0
	MXRaw         string // the MX header as sent, "" when missing
}

// Parse reads an M-SEARCH request from the first 2048 bytes of b and at
// most 32 header lines. It reports false for any other method, a MAN that
// is not "ssdp:discover" and a missing or empty ST.
//
// The header rules follow the daemons of the personas (minidlna
// minissdp.c ProcessSSDPRequest, miniupnpd 2.2.1 minissdp.c
// ProcessSSDPData): the name ends at the colon, blanks and tabs around the
// value are dropped, the value ends at the first CR or LF, a later header
// replaces an earlier one, and MAN only has to start with
// "ssdp:discover" in quotes (strncmp of 15 bytes).
func Parse(b []byte) (Request, bool) {
	var r Request
	if len(b) > maxRead {
		b = b[:maxRead]
	}
	if !bytes.HasPrefix(b, []byte(requestLine)) {
		return r, false
	}
	rest := b[len(requestLine):]
	for n := 0; n < maxHeaders && len(rest) > 0; n++ {
		line := rest
		if i := bytes.Index(rest, []byte("\r\n")); i >= 0 {
			line, rest = rest[:i], rest[i+2:]
		} else {
			rest = nil
		}
		if len(line) == 0 {
			break
		}
		colon := bytes.IndexByte(line, ':')
		if colon < 0 {
			continue
		}
		v := line[colon+1:]
		if i := bytes.IndexAny(v, "\r\n"); i >= 0 {
			v = v[:i]
		}
		val := strings.Trim(string(v), " \t")
		switch name := string(line[:colon]); {
		case strings.EqualFold(name, "ST"):
			r.ST = val
		case strings.EqualFold(name, "MAN"):
			r.MAN = val
		case strings.EqualFold(name, "MX"):
			r.MXRaw = val
		case strings.EqualFold(name, "HOST"):
			r.Host = val
		}
	}
	if r.ST == "" || !strings.HasPrefix(r.MAN, discover) {
		return Request{}, false
	}
	r.MX, r.HasMX = parseMX(r.MXRaw)
	return r, true
}

// parseMX reads the MX value as strtol does in minidlna: an optional sign,
// then at least one digit, the rest ignored. Values above 5 count as 5
// (UPnP Device Architecture 1.1, 1.3.3), negative ones as missing.
func parseMX(s string) (int, bool) {
	i, neg := 0, false
	if i < len(s) && (s[i] == '+' || s[i] == '-') {
		neg = s[i] == '-'
		i++
	}
	start, v := i, 0
	for ; i < len(s) && s[i] >= '0' && s[i] <= '9'; i++ {
		if v < maxMX {
			v = v*10 + int(s[i]-'0')
		}
	}
	if i == start {
		return 0, false
	}
	if neg {
		if v != 0 {
			return 0, false
		}
		return 0, true
	}
	return min(v, maxMX), true
}
