package ntp

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"strconv"
	"time"
)

// ntp_control.h / ntp_control.c.
const (
	ctlHeaderLen  = 12
	ctlMaxDataLen = 468 // CTL_MAX_DATA_LEN
	maxLineLen    = 72  // MAXDATALINELEN
	ctlResponse   = 0x80
	ctlError      = 0x40
	ctlMore       = 0x20
	ctlOpMask     = 0x1f
	opReadvar     = 2 // CTL_OP_READVAR

	// CTL_SYS_STATUS(LEAP_NOWARNING, CTL_SST_TS_NTP, 1, EVNT_SYNC): the
	// status of a host that follows an NTP server. rstclock reports an
	// event only on a change of state and report_event counts events of
	// the same kind, so a host in sync shows one clock_sync event.
	sysStatus = 0<<14 | 6<<8 | 1<<4 | 5
)

// mode6 answers a READVAR request for the system variables as
// process_control and read_variables (ntp_control.c) do. Other control
// requests and READVAR with a variable list get no answer.
func (h *host) mode6(req []byte, now time.Time, ref func() time.Time, r *rand.Rand) [][]byte {
	// process_control: header length, length a multiple of 4, no
	// response, error or more bit, offset 0, version 1-4.
	if len(req) < ctlHeaderLen || len(req)&3 != 0 {
		return nil
	}
	vn := req[0] >> 3 & 7
	op := req[1]
	assoc := binary.BigEndian.Uint16(req[6:])
	offset := binary.BigEndian.Uint16(req[8:])
	count := binary.BigEndian.Uint16(req[10:])
	if vn < oldVersion || vn > version || op&(ctlResponse|ctlError|ctlMore) != 0 || offset != 0 {
		return nil
	}
	if op&ctlOpMask != opReadvar || assoc != 0 || count != 0 {
		return nil
	}
	items := h.sysVars(now, ref, r)
	var frags [][]byte
	for n := len(items); n > 0; n-- {
		if frags = fragment(items[:n], h.old); len(frags) <= 2 {
			break
		}
	}
	if len(frags) > 2 {
		return nil
	}
	out := make([][]byte, len(frags))
	off := 0
	for i, f := range frags {
		d := make([]byte, (ctlHeaderLen+len(f)+3)&^3)
		d[0] = vn<<3 | modeControl // leap 0
		d[1] = ctlResponse | opReadvar
		if i < len(frags)-1 {
			d[1] |= ctlMore
		}
		copy(d[2:4], req[2:4]) // sequence
		binary.BigEndian.PutUint16(d[4:], sysStatus)
		binary.BigEndian.PutUint16(d[8:], uint16(off))
		binary.BigEndian.PutUint16(d[10:], uint16(len(f)))
		copy(d[ctlHeaderLen:], f)
		off += len(f)
		out[i] = d
	}
	return out
}

// item is one variable as the pieces ctl_putstr / ctl_putunqstr hand to
// ctl_putdata_ex.
type item []string

func str(tag, v string) item { return item{tag, `="`, v, `"`} }
func unq(tag, v string) item { return item{tag, "=", v} }
func dbl(tag string, v float64, prec int) item {
	return unq(tag, strconv.FormatFloat(v, 'f', prec, 64))
}

// ts is ctl_putts: "0x%08lx.%08lx" of an NTP timestamp.
func ts(tag string, t time.Time, precision int8, r *rand.Rand) item {
	var b [8]byte
	putStamp(b[:], t, precision, r)
	return unq(tag, fmt.Sprintf("0x%08x.%08x", binary.BigEndian.Uint32(b[:]), binary.BigEndian.Uint32(b[4:])))
}

// sysVars returns the variables of def_sys_var (ntp_control.c) in its
// order, formatted as ctl_putsys does. tai, leapsec and expire need a
// leap second file, the crypto variables a crypto setup; a host without
// them prints none of them.
func (h *host) sysVars(now time.Time, ref func() time.Time, r *rand.Rand) []item {
	n := h.p.NTP
	// ctl_putdbl6 since 4.2.8 for offset and sys_jitter, "%.3f" before.
	fine := 6
	if h.old {
		fine = 3
	}
	sign := 1.0
	if r.Intn(2) == 0 {
		sign = -1
	}
	return []item{
		str("version", n.ReadvarVersion),
		str("processor", n.Processor),
		str("system", n.System),
		unq("leap", "0"),
		unq("stratum", strconv.Itoa(int(n.Stratum))),
		unq("precision", strconv.Itoa(int(n.Precision))),
		dbl("rootdelay", jitter(h.p.RootDelay, r)*1e3, 3),
		dbl("rootdisp", jitter(h.p.RootDisp, r)*1e3, 3),
		unq("refid", h.p.RefID.String()),
		ts("reftime", ref(), n.Precision, r),
		ts("clock", now, n.Precision, r),
		unq("peer", strconv.Itoa(int(h.assoc))),
		unq("tc", strconv.Itoa(int(n.PollLog))),
		unq("mintc", strconv.Itoa(minPoll)),
		dbl("offset", sign*(0.005+r.Float64()*0.9), fine),
		dbl("frequency", h.freq+(r.Float64()*2-1)*0.005, 3),
		dbl("sys_jitter", 0.05+r.Float64()*1.5, fine),
		dbl("clk_jitter", 0.02+r.Float64()*0.8, 3),
		dbl("clk_wander", 0.001+r.Float64()*0.09, 3),
	}
}

// fragment lays the items out as ntpd's ctl_putdata and ctl_flushpkt do
// and returns the data of each response fragment, at most
// CTL_MAX_DATA_LEN bytes each.
func fragment(items []item, old bool) [][]byte {
	if old {
		return fragment426(items)
	}
	return fragment428(items)
}

// fragment428 follows ctl_putdata_ex of ntpd 4.2.8: ", " between items,
// ",\r\n" when the item would reach MAXDATALINELEN, each piece copied up
// to the end of the fragment with 3 bytes kept free, the rest of a piece
// that does not fit in the next fragment. ctl_flushpkt ends the last
// fragment with "\r\n" if it fits.
func fragment428(items []item) [][]byte {
	var frags [][]byte
	cur := make([]byte, 0, ctlMaxDataLen)
	line := 0
	for i, it := range items {
		if i > 0 {
			cur = append(cur, ',')
			line++
			n := 0
			for _, p := range it {
				n += len(p)
			}
			if n+line+1 >= maxLineLen {
				cur = append(cur, '\r', '\n')
				line = 0
			} else {
				cur = append(cur, ' ')
				line++
			}
		}
		for _, p := range it {
			if p == "" {
				continue
			}
			for room := ctlMaxDataLen - len(cur); len(p)+3 > room; room = ctlMaxDataLen - len(cur) {
				k := min(room, len(p))
				cur = append(cur, p[:k]...)
				line += k
				p = p[k:]
				frags = append(frags, cur)
				cur = make([]byte, 0, ctlMaxDataLen)
			}
			cur = append(cur, p...)
			line += len(p)
		}
	}
	if len(cur)+2 < ctlMaxDataLen {
		cur = append(cur, '\r', '\n')
	}
	return append(frags, cur)
}

// fragment426 follows ctl_putdata of ntpd 4.2.6: the separator only
// after an item of the same fragment, an item that does not fit with 3
// bytes to spare starts the next fragment, and ctl_flushpkt always ends
// the last fragment with "\r\n". ctl_putstr cuts a string to its buffer
// of 400 bytes.
func fragment426(items []item) [][]byte {
	var frags [][]byte
	cur := make([]byte, 0, ctlMaxDataLen)
	line := 0
	for _, it := range items {
		s := ""
		for _, p := range it {
			s += p
		}
		if len(s) > 400 && len(it) == 4 {
			s = s[:399] + `"`
		}
		if len(cur) > 0 {
			cur = append(cur, ',')
			line++
			if len(s)+line+1 >= maxLineLen {
				cur = append(cur, '\r', '\n')
				line = 0
			} else {
				cur = append(cur, ' ')
				line++
			}
		}
		if len(cur)+len(s)+3 > ctlMaxDataLen {
			frags = append(frags, cur)
			cur = make([]byte, 0, ctlMaxDataLen)
		}
		cur = append(cur, s...)
		line += len(s)
	}
	return append(frags, append(cur, '\r', '\n'))
}
