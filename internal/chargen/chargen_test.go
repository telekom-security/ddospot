package chargen

import (
	"strings"
	"testing"
	"time"

	"github.com/t3chn0m4g3/ddospot/internal/limit"
	"github.com/t3chn0m4g3/ddospot/internal/testutil"
)

func TestResponseShape(t *testing.T) {
	r := Response(0)
	if len(r) != Size {
		t.Fatal(len(r))
	}
	lines := strings.Split(string(r), "\r\n")
	if len(lines[0]) != 72 || lines[0][0] != '!' {
		t.Fatalf("%q", lines[0])
	}
	if Response(1)[0] != '"' {
		t.Fatal("no rotation")
	}
	for _, c := range r {
		if c != '\r' && c != '\n' && (c < 32 || c > 126) {
			t.Fatalf("byte %d", c)
		}
	}
}

func TestServeAnswersAndBudget(t *testing.T) {
	srv, cli := testutil.UDPPair(t)
	lim := limit.New(limit.Defaults(time.Minute), time.Now, testutil.NopObs{})
	go New(srv, lim).Serve()
	got := 0
	for i := 0; i < 7; i++ {
		cli.Write([]byte("x"))
		if testutil.ReadTimeout(cli, 300*time.Millisecond) == Size {
			got++
		}
	}
	if got != 5 {
		t.Fatalf("answers %d, want 5", got)
	}
}

func FuzzResponse(f *testing.F) {
	f.Add(0)
	f.Fuzz(func(t *testing.T, o int) {
		if len(Response(o)) != Size {
			t.Fatal()
		}
	})
}
