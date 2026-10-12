// Package bucket is a token bucket without a clock or a lock of its own.
package bucket

import "time"

// Bucket holds up to burst tokens and gains rate tokens per second.
// It is not safe for concurrent use; callers hold their own mutex.
type Bucket struct {
	rate, burst, tokens float64
	last                time.Time
}

// New returns a full bucket.
func New(rate, burst float64) *Bucket {
	return &Bucket{rate: rate, burst: burst, tokens: burst}
}

func (b *Bucket) refill(now time.Time) {
	if b.last.IsZero() {
		b.last = now
		return
	}
	if d := now.Sub(b.last); d > 0 {
		b.tokens += d.Seconds() * b.rate
		if b.tokens > b.burst {
			b.tokens = b.burst
		}
		b.last = now
	}
}

// Can refills the bucket and reports whether n tokens are available.
func (b *Bucket) Can(n float64, now time.Time) bool {
	b.refill(now)
	return b.tokens >= n
}

// Take removes n tokens if they are available and reports whether it did.
// A refused take leaves the bucket as it was.
func (b *Bucket) Take(n float64, now time.Time) bool {
	if !b.Can(n, now) {
		return false
	}
	b.tokens -= n
	return true
}
