// Package jsonlog writes one JSON object per line into the five log files
// of the honeypot, with a line budget.
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
	lineRate  = 200
	lineBurst = 400
)

var allowed = map[string]bool{
	"chargenpot.log": true,
	"dnspot.log":     true,
	"ntpot.log":      true,
	"ssdpot.log":     true,
	"targets.log":    true,
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
	bucket  *bucket.Bucket
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
		dir:    dir,
		now:    now,
		files:  map[string]*os.File{},
		bucket: bucket.New(lineRate, lineBurst),
	}, nil
}

// Write appends ev as one line to file, which must be one of the five log
// file names (anything else is a programming error and panics). Keys are
// sorted. A nil event writes nothing. A line beyond the budget is counted by
// Dropped, a line lost to an error by Errors.
func (w *Writer) Write(file string, ev map[string]any) {
	if !allowed[file] {
		panic("jsonlog: unknown log file " + file)
	}
	if ev == nil {
		return
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return
	}
	if enc.Encode(ev) != nil {
		w.errors++
		return
	}
	now := w.now()
	if !w.bucket.Can(1, now) {
		w.dropped++
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
	w.bucket.Take(1, now)
	if n, err := f.Write(buf.Bytes()); err != nil || n != buf.Len() {
		w.errors++
	}
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
