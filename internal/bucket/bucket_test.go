package bucket

import (
	"testing"
	"time"
)

func TestRefillAndBurst(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	b := New(10, 20)
	if !b.Take(20, now) {
		t.Fatal("a new bucket is not full")
	}
	if b.Can(1, now) {
		t.Fatal("empty bucket allows a take")
	}
	if !b.Can(10, now.Add(time.Second)) || b.Can(11, now.Add(time.Second)) {
		t.Fatal("one second does not refill exactly rate tokens")
	}
	if !b.Can(20, now.Add(time.Hour)) || b.Can(21, now.Add(time.Hour)) {
		t.Fatal("tokens exceed burst")
	}
}

func TestRefusedTakeSubtractsNothing(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	b := New(5, 5)
	if b.Take(6, now) {
		t.Fatal("take above the burst succeeded")
	}
	if !b.Take(5, now) {
		t.Fatal("refused take consumed tokens")
	}
}

func TestZeroTake(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	b := New(5, 5)
	b.Take(5, now)
	if !b.Can(0, now) || !b.Take(0, now) {
		t.Fatal("zero-size take refused")
	}
}
