package jsonlog

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestTimeFormat(t *testing.T) {
	got := Time(time.Date(2026, 10, 11, 9, 8, 7, 0, time.FixedZone("x", 7200)))
	if got != "2026-10-11 07:08:07.000000" {
		t.Fatal(got)
	}
}

func TestWriteAppendsJSONLines(t *testing.T) {
	d := t.TempDir()
	now := time.Unix(0, 0)
	w := mustOpen(t, d, func() time.Time { return now })
	w.Write("ntpot.log", map[string]any{"src_ip": "192.0.2.1", "mode": "DATA"})
	w.Write("ntpot.log", map[string]any{"src_ip": "192.0.2.2"})
	w.Close()
	b, _ := os.ReadFile(filepath.Join(d, "ntpot.log"))
	lines := strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("%q", b)
	}
	for _, l := range lines {
		var m map[string]any
		if json.Unmarshal([]byte(l), &m) != nil {
			t.Fatalf("not JSON: %q", l)
		}
	}
}

func TestWriteBudget(t *testing.T) {
	d := t.TempDir()
	now := time.Unix(0, 0)
	w := mustOpen(t, d, func() time.Time { return now })
	for i := 0; i < 1000; i++ {
		w.Write("targets.log", map[string]any{"i": i})
	}
	if got := w.Dropped(); got != 600 {
		t.Fatalf("dropped %d, want 600", got)
	}
	if got := w.Dropped(); got != 0 {
		t.Fatalf("counter not reset: %d", got)
	}
}

func TestUnknownFilePanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("no panic")
		}
	}()
	w := mustOpen(t, t.TempDir(), time.Now)
	w.Write("../x.log", nil)
}

func TestSortedKeysNoHTMLEscaping(t *testing.T) {
	d := t.TempDir()
	w := mustOpen(t, d, time.Now)
	w.Write("dnspot.log", map[string]any{"z": "a<b>&c", "a": 1})
	w.Close()
	b, _ := os.ReadFile(filepath.Join(d, "dnspot.log"))
	if string(b) != "{\"a\":1,\"z\":\"a<b>&c\"}\n" {
		t.Fatalf("%q", b)
	}
}

func TestOpenAppendsToExistingFile(t *testing.T) {
	d := t.TempDir()
	if err := os.WriteFile(filepath.Join(d, "ssdpot.log"), []byte("old\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	w := mustOpen(t, d, time.Now)
	w.Write("ssdpot.log", map[string]any{"st": "x"})
	w.Close()
	b, _ := os.ReadFile(filepath.Join(d, "ssdpot.log"))
	if !strings.HasPrefix(string(b), "old\n{") {
		t.Fatalf("%q", b)
	}
}

func TestConcurrentWrites(t *testing.T) {
	d := t.TempDir()
	w := mustOpen(t, d, time.Now)
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 20; i++ {
				w.Write("chargenpot.log", map[string]any{"i": i})
				w.Dropped()
			}
		}()
	}
	wg.Wait()
	w.Close()
	b, _ := os.ReadFile(filepath.Join(d, "chargenpot.log"))
	for _, l := range strings.Split(strings.TrimSuffix(string(b), "\n"), "\n") {
		var m map[string]any
		if json.Unmarshal([]byte(l), &m) != nil {
			t.Fatalf("not JSON: %q", l)
		}
	}
}

func mustOpen(t *testing.T, dir string, now func() time.Time) *Writer {
	t.Helper()
	w, err := Open(dir, now)
	if err != nil {
		t.Fatal(err)
	}
	return w
}

func TestOpenFailureCountsError(t *testing.T) {
	d := t.TempDir()
	if err := os.Mkdir(filepath.Join(d, "ntpot.log"), 0o750); err != nil {
		t.Fatal(err)
	}
	w := mustOpen(t, d, time.Now)
	w.Write("ntpot.log", map[string]any{"a": 1})
	if got := w.Errors(); got != 1 {
		t.Fatalf("errors %d, want 1", got)
	}
	if got := w.Errors(); got != 0 {
		t.Fatalf("counter not reset: %d", got)
	}
	w.Close()
}

func TestFailedOpenKeepsBudget(t *testing.T) {
	d := t.TempDir()
	if err := os.Mkdir(filepath.Join(d, "ntpot.log"), 0o750); err != nil {
		t.Fatal(err)
	}
	now := time.Unix(0, 0)
	w := mustOpen(t, d, func() time.Time { return now })
	for i := 0; i < 1000; i++ {
		w.Write("ntpot.log", map[string]any{"i": i})
	}
	for i := 0; i < 400; i++ {
		w.Write("targets.log", map[string]any{"i": i})
	}
	if got := w.Dropped(); got != 0 {
		t.Fatalf("dropped %d, want 0", got)
	}
	if got := w.Errors(); got != 1000 {
		t.Fatalf("errors %d, want 1000", got)
	}
	w.Close()
}

func TestEncodeFailureCountsError(t *testing.T) {
	w := mustOpen(t, t.TempDir(), time.Now)
	w.Write("dnspot.log", map[string]any{"c": make(chan int)})
	if got := w.Errors(); got != 1 {
		t.Fatalf("errors %d, want 1", got)
	}
	w.Close()
}

func TestNilEventWritesNothing(t *testing.T) {
	d := t.TempDir()
	w := mustOpen(t, d, time.Now)
	w.Write("ssdpot.log", nil)
	w.Close()
	if b, _ := os.ReadFile(filepath.Join(d, "ssdpot.log")); len(b) != 0 {
		t.Fatalf("%q", b)
	}
}
