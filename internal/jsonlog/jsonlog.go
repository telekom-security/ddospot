// Package jsonlog writes one JSON object per line into the five log files
// of the honeypot, with line budgets: one shared by the four scanner files
// and one for targets.log.
package jsonlog

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/t3chn0m4g3/ddospot/internal/bucket"
)

const (
	lineRate         = 200
	lineBurst        = 400
	targetsLineBurst = 2000
	targetsFile      = "targets.log"
)

var allowed = map[string]bool{
	"chargenpot.log": true,
	"dnspot.log":     true,
	"ntpot.log":      true,
	"ssdpot.log":     true,
	targetsFile:      true,
}

// Time formats t as UTC "2006-01-02 15:04:05.000000".
func Time(t time.Time) string {
	return t.UTC().Format("2006-01-02 15:04:05.000000")
}

// Writer appends JSON lines to files in one directory. It is safe for
// concurrent use.
type Writer struct {
	dir     string
	now     func() time.Time
	mu      sync.Mutex
	files   map[string]*os.File
	scanner *bucket.Bucket
	targets *bucket.Bucket
	dropped uint64
	errors  uint64
	closed  bool
}

// Open returns a writer for dir. Files are opened on first use. The
// directory is created if it is missing.
func Open(dir string, now func() time.Time) (*Writer, error) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, err
	}
	return &Writer{
		dir:     dir,
		now:     now,
		files:   map[string]*os.File{},
		scanner: bucket.New(lineRate, lineBurst),
		targets: bucket.New(lineRate, targetsLineBurst),
	}, nil
}

// budget returns the line budget of file: targets.log has its own, the four
// scanner files share one.
func (w *Writer) budget(file string) *bucket.Bucket {
	if file == targetsFile {
		return w.targets
	}
	return w.scanner
}

// Write appends ev as one line to file, which must be one of the five log
// file names (anything else is a programming error and panics). Keys are
// sorted. A nil event writes nothing. A line beyond the budget is counted by
// Dropped and not encoded, a line lost to an error by Errors.
func (w *Writer) Write(file string, ev map[string]any) {
	if !allowed[file] {
		panic("jsonlog: unknown log file " + file)
	}
	if ev == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return
	}
	now := w.now()
	b := w.budget(file)
	if !b.Can(1, now) {
		w.dropped++
		return
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if enc.Encode(ev) != nil {
		w.errors++
		return
	}
	f := w.files[file]
	if f == nil {
		var err error
		f, err = os.OpenFile(filepath.Join(w.dir, file), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
		if err != nil {
			w.errors++
			return
		}
		w.files[file] = f
	}
	b.Take(1, now)
	if n, err := f.Write(buf.Bytes()); err != nil || n != buf.Len() {
		w.errors++
	}
}

// Allow reports whether a line for file would be written now, without
// taking from the budget, so that a caller can skip building an event that
// would be left out. A false answer with the budget spent counts that line
// in Dropped; after Close the answer is false and nothing is counted. file
// must be one of the five log file names, as for Write.
func (w *Writer) Allow(file string) bool {
	if !allowed[file] {
		panic("jsonlog: unknown log file " + file)
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return false
	}
	if !w.budget(file).Can(1, w.now()) {
		w.dropped++
		return false
	}
	return true
}

// Dropped returns the number of lines left out by the budget since the last
// call and resets the counter.
func (w *Writer) Dropped() uint64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	n := w.dropped
	w.dropped = 0
	return n
}

// Errors returns the number of lines lost to encode, open or write failures
// since the last call and resets the counter.
func (w *Writer) Errors() uint64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	n := w.errors
	w.errors = 0
	return n
}

// Close closes all open files. Later writes are ignored.
func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.closed = true
	var first error
	for name, f := range w.files {
		if err := f.Close(); err != nil && first == nil {
			first = err
		}
		delete(w.files, name)
	}
	return first
}
