package ntp

import (
	"encoding/binary"
	"math/rand"
	"time"
)

// lenPkt is LEN_PKT_NOMAC of ntp.h: the NTP header without MAC.
const lenPkt = 48

// mode3 answers a client request as ntpd's fast_xmit (ntp_proto.c) does
// for a host without MAC: leap, the request version, mode 4, the system
// stratum, max(request poll, ntp_minpoll), the system precision, root
// delay and dispersion, refid and reftime, the request transmit time as
// origin, then receive and transmit time.
func (h *host) mode3(req []byte, now time.Time, ref func() time.Time, r *rand.Rand) []byte {
	// receive: shorter packets are dropped, longer ones carry a MAC or
	// extension fields that are checked against the keys of the host,
	// which has none.
	if len(req) != lenPkt {
		return nil
	}
	// receive: version 1 to 7 are taken unless "restrict version" is set.
	vn := req[0] >> 3 & 7
	if vn < oldVersion {
		return nil
	}
	n := h.p.NTP
	d := make([]byte, lenPkt)
	d[0] = vn<<3 | modeServer // leap 0
	d[1] = n.Stratum
	d[2] = max(req[2], minPoll)
	d[3] = byte(n.Precision)
	// HTONS_FP(DTOFP()) / DTOUFP(): seconds as 16.16 fixed point.
	binary.BigEndian.PutUint32(d[4:], uint32(jitter(h.p.RootDelay, r)*65536))
	binary.BigEndian.PutUint32(d[8:], uint32(jitter(h.p.RootDisp, r)*65536))
	copy(d[12:16], h.p.RefID.AsSlice())
	putStamp(d[16:], ref(), n.Precision, r)
	copy(d[24:32], req[40:48])
	putStamp(d[32:], now, n.Precision, r)
	xmt := now.Add(20*time.Microsecond + time.Duration(r.Int63n(int64(180*time.Microsecond)+1)))
	putStamp(d[40:], xmt, n.Precision, r)
	return d
}
