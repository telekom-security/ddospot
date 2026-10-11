package ntp

import (
	"encoding/binary"
	"math/rand"
	"net/netip"
	"testing"
	"time"
)

// stamp decodes a 64-bit NTP timestamp of era 0.
func stamp(b []byte) time.Time {
	sec := int64(binary.BigEndian.Uint32(b)) - 2208988800
	frac := int64(binary.BigEndian.Uint32(b[4:]))
	return time.Unix(sec, frac*1e9>>32).UTC()
}

func short(b []byte) float64 { return float64(binary.BigEndian.Uint32(b)) / 65536 }

func TestMode3Fields(t *testing.T) {
	p := per("centos7")
	r, _ := Answer(p, client(4), src(), now, rand.New(rand.NewSource(3)))
	d := r[0]
	if d[1] != p.NTP.Stratum || int8(d[3]) != p.NTP.Precision {
		t.Fatalf("stratum %d precision %d", d[1], int8(d[3]))
	}
	if d[2] != 6 {
		t.Fatalf("poll %d", d[2])
	}
	if got := netip.AddrFrom4([4]byte(d[12:16])); got != p.RefID {
		t.Fatalf("refid %s", got)
	}
	if v := short(d[4:8]); v < p.RootDelay*0.9-1e-4 || v > p.RootDelay*1.1 {
		t.Fatalf("root delay %f of %f", v, p.RootDelay)
	}
	if v := short(d[8:12]); v < p.RootDisp*0.9-1e-4 || v > p.RootDisp*1.1 {
		t.Fatalf("root dispersion %f of %f", v, p.RootDisp)
	}
	rec, xmt := stamp(d[32:40]), stamp(d[40:48])
	if dt := rec.Sub(now); dt < -time.Microsecond || dt > time.Microsecond {
		t.Fatalf("receive %v", rec)
	}
	if dt := xmt.Sub(rec); dt < 19*time.Microsecond || dt > 201*time.Microsecond {
		t.Fatalf("transmit after receive %v", dt)
	}
	ref := stamp(d[16:24])
	step := time.Unix(now.Unix()&^(1<<p.NTP.PollLog-1), 0)
	if ref.After(step) || ref.Before(step.Add(-2*time.Second-time.Microsecond)) {
		t.Fatalf("reftime %v, step %v", ref, step)
	}
}

// ntpd answers with the request version (fast_xmit) and drops version 0
// (receive); the poll is max(request poll, ntp_minpoll = 3).
func TestMode3VersionAndPoll(t *testing.T) {
	p := per("debian11")
	if r, _ := Answer(p, client(0), src(), now, rand.New(rand.NewSource(1))); r != nil {
		t.Fatal("version 0 answered")
	}
	r, _ := Answer(p, client(5), src(), now, rand.New(rand.NewSource(1)))
	if len(r) != 1 || r[0][0] != 5<<3|4 {
		t.Fatalf("version 5: %v", r)
	}
	for in, want := range map[byte]byte{0: 3, 3: 3, 6: 6, 10: 10, 17: 17} {
		req := client(4)
		req[2] = in
		r, _ := Answer(p, req, src(), now, rand.New(rand.NewSource(1)))
		if r[0][2] != want {
			t.Fatalf("poll %d answered %d, want %d", in, r[0][2], want)
		}
	}
}

func TestMode3LegacyModeZero(t *testing.T) {
	req := client(1)
	req[0] = 1 << 3
	r, m := Answer(per("debian11"), req, src(), now, rand.New(rand.NewSource(1)))
	if m != "DATA" || len(r) != 1 || r[0][0] != 1<<3|4 {
		t.Fatalf("%v %v", m, r)
	}
	req[0] = 2 << 3
	if r, _ := Answer(per("debian11"), req, src(), now, rand.New(rand.NewSource(1))); r != nil {
		t.Fatal("mode 0 version 2 answered")
	}
}

func TestMode3TrailingBytes(t *testing.T) {
	req := append(client(4), 0, 0, 0, 0)
	if r, _ := Answer(per("debian11"), req, src(), now, rand.New(rand.NewSource(1))); r != nil {
		t.Fatal("request with trailing bytes answered")
	}
}

func TestReftimeKeepsTwoSteps(t *testing.T) {
	s := New(nil, nil, per("debian11"))
	for i := 0; i < 10; i++ {
		s.reftime(now.Add(time.Duration(i) * 1100 * time.Second))
	}
	if len(s.steps) > 2 {
		t.Fatalf("%d steps kept", len(s.steps))
	}
	a := s.reftime(now.Add(9 * 1100 * time.Second))
	b := s.reftime(now.Add(9*1100*time.Second + time.Second))
	if !a.Equal(b) {
		t.Fatal("current step rolled again")
	}
}
