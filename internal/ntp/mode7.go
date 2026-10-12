package ntp

import (
	"encoding/binary"
	"math/rand"
	"net/netip"
	"sort"
	"time"

	"github.com/telekom-security/ddospot/internal/persona"
)

// ntp_request.h.
const (
	respBit       = 0x80
	moreBit       = 0x40
	implXntpdOld  = 2 // IMPL_XNTPD_OLD: items without the IPv6 part
	implXntpd     = 3 // IMPL_XNTPD
	reqMonGetlist = 20
	reqMonList1   = 42 // REQ_MON_GETLIST_1
	respHeaderLen = 8

	// The data of one answer stays within 472 bytes, so a datagram is
	// at most 480 bytes long. For items of 72 bytes this is the six
	// items that RESP_DATA_SIZE (500) holds.
	maxRespData  = 472
	maxDatagrams = 2
	maxEntries   = 12

	// restrict flags of "restrict default kod nomodify notrap nopeer"
	// as ntp_monitor keeps them: RES_NOPEER | RES_NOMODIFY | RES_NOTRAP,
	// RES_KOD and RES_LIMITED cleared.
	monRestrict = 0x0010 | 0x0080 | 0x0100
	mdfUcast    = 0x01 // MDF_UCAST
	ntpPort     = 123
)

// monPeer is one host of the monitor list besides the requester. It sends
// a packet every period seconds; phase is the time of one of them.
type monPeer struct {
	addr          netip.Addr
	mode          uint8
	period, first int64
	phase         int64
}

// rollMonitor returns the monitor list of the persona's ntpd at now: its
// time servers answer in mode 4 every 2^PollLog s, the clients of its LAN
// ask in mode 3 every 64 to 1024 s, all from port 123 with version 4.
func rollMonitor(p *persona.Persona, r *rand.Rand, now time.Time) []monPeer {
	lan := netip.PrefixFrom(p.LAN, 24).Masked()
	t0 := now.Unix()
	var out []monPeer
	for _, a := range p.Peers {
		m := monPeer{addr: a, mode: modeServer, period: 1 << p.NTP.PollLog}
		if lan.Contains(a) {
			m.mode = modeClient
			m.period = 1 << (6 + r.Intn(5))
		}
		m.phase = t0 - r.Int63n(m.period)
		count := int64(20 + r.Intn(381))
		if boot := int64(p.BootID); boot > 0 && boot < m.phase {
			count = max(1, min(count, (m.phase-boot)/m.period+1))
		}
		m.first = m.phase - (count-1)*m.period
		out = append(out, m)
	}
	return out
}

// at returns the values mon_getlist reports at now: the average
// interval (now - first) / count, the seconds since the last packet and
// the packet count. ok is false before the first packet.
func (m monPeer) at(now int64) (avg, last, count uint32, ok bool) {
	k := (now - m.phase) / m.period
	if now < m.phase && (now-m.phase)%m.period != 0 {
		k--
	}
	lastPkt := m.phase + k*m.period
	if lastPkt < m.first {
		return 0, 0, 0, false
	}
	n := (lastPkt-m.first)/m.period + 1
	return uint32((now - m.first) / n), uint32(now - lastPkt), uint32(n), true
}

type monEntry struct {
	avg, last, count uint32
	addr             netip.Addr
	port             uint16
	mode, version    uint8
}

// mode7 answers MON_GETLIST and MON_GETLIST_1 as process_private and
// mon_getlist_0 / mon_getlist_1 (ntp_request.c) do, for ntpd releases
// that have them. Other requests and IPv6 requesters get no answer.
func (h *host) mode7(req []byte, src netip.AddrPort, now time.Time) [][]byte {
	if !h.p.NTP.Monlist || len(req) < respHeaderLen {
		return nil
	}
	// process_private: no response or more bit, version 1-4, sequence 0,
	// no error code, mbz 0; the request codes of the monitor list carry
	// no items, so the item size is 0.
	vn := req[0] >> 3 & 7
	if req[0]&(respBit|moreBit) != 0 || vn < oldVersion || vn > version ||
		req[1]&0x7f != 0 || req[4]>>4 != 0 || binary.BigEndian.Uint16(req[6:]) != 0 {
		return nil
	}
	impl, code := req[2], req[3]
	if impl != implXntpd && impl != implXntpdOld || code != reqMonGetlist && code != reqMonList1 {
		return nil
	}
	addr := src.Addr().Unmap()
	if !addr.Is4() {
		return nil
	}

	// struct info_monitor_1 (72 bytes) or info_monitor (48 bytes); the
	// IPv6 part from v6_flag on only for implementation 3 (v6sizeof).
	var size int
	switch {
	case code == reqMonList1 && impl == implXntpd:
		size = 72
	case code == reqMonList1:
		size = 32
	case impl == implXntpd:
		size = 48
	default:
		size = 24
	}

	// ntp_monitor puts the request on top of the MRU list before it is
	// answered.
	list := []monEntry{{count: 1, addr: addr, port: src.Port(), mode: modePrivate, version: vn}}
	var rest []monEntry
	t := now.Unix()
	for _, m := range h.mon {
		if m.addr == addr {
			continue
		}
		if avg, last, count, ok := m.at(t); ok {
			rest = append(rest, monEntry{avg, last, count, m.addr, ntpPort, m.mode, version})
		}
	}
	sort.SliceStable(rest, func(i, j int) bool { return rest[i].last < rest[j].last })
	list = append(list, rest...)

	per := maxRespData / size
	list = list[:min(len(list), maxEntries, maxDatagrams*per)]

	var out [][]byte
	for seq := 0; len(list) > 0; seq++ {
		n := min(per, len(list))
		d := make([]byte, respHeaderLen+n*size)
		d[0] = respBit | vn<<3 | modePrivate
		if n < len(list) {
			d[0] |= moreBit
		}
		d[1] = byte(seq)
		d[2], d[3] = impl, code
		binary.BigEndian.PutUint16(d[4:], uint16(n))
		binary.BigEndian.PutUint16(d[6:], uint16(size))
		for i, e := range list[:n] {
			h.putMonEntry(d[respHeaderLen+i*size:], e, code)
		}
		out = append(out, d)
		list = list[n:]
	}
	return out
}

// putMonEntry writes the IPv4 part of an item; the IPv6 part stays zero.
func (h *host) putMonEntry(b []byte, e monEntry, code byte) {
	binary.BigEndian.PutUint32(b, e.avg)
	binary.BigEndian.PutUint32(b[4:], e.last)
	binary.BigEndian.PutUint32(b[8:], monRestrict)
	binary.BigEndian.PutUint32(b[12:], e.count)
	copy(b[16:20], e.addr.AsSlice())
	b = b[20:]
	if code == reqMonList1 {
		// mon_getlist_1: a unicast packet reports the address of the
		// interface it came in on, and the cast flags.
		copy(b[0:4], h.p.LAN.AsSlice())
		binary.BigEndian.PutUint32(b[4:], mdfUcast)
		b = b[8:]
	}
	binary.BigEndian.PutUint16(b, e.port)
	b[2], b[3] = e.mode, e.version
}
