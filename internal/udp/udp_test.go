package udp

import (
	"errors"
	"net"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/t3chn0m4g3/ddospot/internal/testutil"
)

func TestLoopReturnsAfterClose(t *testing.T) {
	srv, _ := testutil.UDPPair(t)
	done := make(chan error, 1)
	go func() { done <- Loop(srv, func([]byte, netip.AddrPort) {}) }()
	time.Sleep(50 * time.Millisecond)
	srv.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Loop did not return")
	}
}

func TestLoopHandlesDatagrams(t *testing.T) {
	srv, cli := testutil.UDPPair(t)
	type got struct {
		req string
		src netip.AddrPort
	}
	ch := make(chan got, 2)
	go Loop(srv, func(req []byte, src netip.AddrPort) { ch <- got{string(req), src} })
	want := cli.LocalAddr().(*net.UDPAddr).AddrPort()
	for _, p := range []string{"abc", ""} {
		cli.Write([]byte(p))
		select {
		case g := <-ch:
			if g.req != p || g.src != want {
				t.Fatalf("got %q from %v, want %q from %v", g.req, g.src, p, want)
			}
		case <-time.After(time.Second):
			t.Fatalf("no call for %q", p)
		}
	}
}

func TestLoopBackoff(t *testing.T) {
	boom := errors.New("read failed")
	type step struct {
		n   int
		err error
	}
	var steps []step
	for i := 0; i < 13; i++ {
		steps = append(steps, step{err: boom})
	}
	steps = append(steps, step{n: 3}, step{err: boom}, step{err: net.ErrClosed})
	i := 0
	read := func(b []byte) (int, netip.AddrPort, error) {
		s := steps[i]
		i++
		return s.n, netip.AddrPort{}, s.err
	}
	calls := 0
	var slept []time.Duration
	err := loop(read, func([]byte, netip.AddrPort) { calls++ }, func(d time.Duration) { slept = append(slept, d) })
	if err != nil || calls != 1 {
		t.Fatalf("err %v calls %d", err, calls)
	}
	want := []time.Duration{}
	d := time.Millisecond
	for k := 0; k < 13; k++ {
		want = append(want, d)
		if d *= 2; d > time.Second {
			d = time.Second
		}
	}
	want = append(want, time.Millisecond)
	if !reflect.DeepEqual(slept, want) {
		t.Fatalf("sleeps %v, want %v", slept, want)
	}
	if want[10] != time.Second || want[12] != time.Second {
		t.Fatal("cap not reached")
	}
}
