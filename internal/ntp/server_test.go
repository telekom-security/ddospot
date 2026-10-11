package ntp

import (
	"net"
	"testing"
	"time"

	"github.com/t3chn0m4g3/ddospot/internal/limit"
	"github.com/t3chn0m4g3/ddospot/internal/testutil"
)

// answered sends req and reports whether at least one datagram came back;
// it reads every fragment of the answer so the next request starts clean.
func answered(t *testing.T, c *net.UDPConn, req []byte) bool {
	t.Helper()
	if _, err := c.Write(req); err != nil {
		t.Fatal(err)
	}
	if testutil.ReadTimeout(c, 300*time.Millisecond) == 0 {
		return false
	}
	for testutil.ReadTimeout(c, 50*time.Millisecond) > 0 {
	}
	return true
}

func TestServeBudgetPerSource(t *testing.T) {
	srv, cli := testutil.UDPPair(t)
	lim := limit.New(limit.Defaults(time.Minute), time.Now, testutil.NopObs{})
	go New(srv, lim, per("debian11")).Serve()
	got := 0
	for i := 0; i < 7; i++ {
		if answered(t, cli, client(4)) {
			got++
		}
	}
	if got != 5 {
		t.Fatalf("answers %d, want 5", got)
	}
}

func TestServeBudgetSharedAcrossModes(t *testing.T) {
	srv, cli := testutil.UDPPair(t)
	lim := limit.New(limit.Defaults(time.Minute), time.Now, testutil.NopObs{})
	go New(srv, lim, per("debian11")).Serve()
	readvar := []byte{0x16, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, 0}
	got := 0
	for i := 0; i < 3; i++ {
		if answered(t, cli, client(4)) {
			got++
		}
	}
	for i := 0; i < 4; i++ {
		if answered(t, cli, readvar) {
			got++
		}
	}
	if got != 5 {
		t.Fatalf("answers %d, want 5", got)
	}
}

func TestServeIgnoresUnansweredPackets(t *testing.T) {
	srv, cli := testutil.UDPPair(t)
	lim := limit.New(limit.Defaults(time.Minute), time.Now, testutil.NopObs{})
	go New(srv, lim, per("debian11")).Serve()
	for i := 0; i < 10; i++ {
		if answered(t, cli, []byte("x")) {
			t.Fatal("answer to a packet without NTP header")
		}
	}
	// Packets without an answer take nothing from the budget.
	got := 0
	for i := 0; i < 5; i++ {
		if answered(t, cli, client(4)) {
			got++
		}
	}
	if got != 5 {
		t.Fatalf("answers %d, want 5", got)
	}
}

func TestServeReturnsAfterClose(t *testing.T) {
	srv, _ := testutil.UDPPair(t)
	lim := limit.New(limit.Defaults(time.Minute), time.Now, testutil.NopObs{})
	done := make(chan error, 1)
	go func() { done <- New(srv, lim, per("debian11")).Serve() }()
	time.Sleep(50 * time.Millisecond)
	srv.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Serve did not return")
	}
}
