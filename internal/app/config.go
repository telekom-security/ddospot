package app

import (
	"fmt"
	"strconv"
	"time"
)

// Config holds the settings of a run.
type Config struct {
	LogDir    string
	Recursion bool          // DNS recursion through the upstream resolver
	Classify  time.Duration // classification hold of a new source

	// Listen addresses of the pots; DNS is used for UDP and TCP.
	Chargen, DNS, NTP, SSDP string
}

const (
	minClassify = 1
	maxClassify = 600
)

// FromEnv reads the settings from the environment through getenv:
// DDOSPOT_LOG_DIR (default /var/log/ddospot), DDOSPOT_DNS_RECURSION (on or
// off, default on) and DDOSPOT_CLASSIFY_SECONDS (integer 1-600, default 60).
// The pots listen on their well-known ports on all addresses.
func FromEnv(getenv func(string) string) (Config, error) {
	c := Config{
		LogDir:    "/var/log/ddospot",
		Recursion: true,
		Classify:  60 * time.Second,
		Chargen:   ":19",
		DNS:       ":53",
		NTP:       ":123",
		SSDP:      ":1900",
	}
	if v := getenv("DDOSPOT_LOG_DIR"); v != "" {
		c.LogDir = v
	}
	switch v := getenv("DDOSPOT_DNS_RECURSION"); v {
	case "", "on":
	case "off":
		c.Recursion = false
	default:
		return Config{}, fmt.Errorf("DDOSPOT_DNS_RECURSION must be on or off, got %q", v)
	}
	if v := getenv("DDOSPOT_CLASSIFY_SECONDS"); v != "" {
		n, ok := digits(v)
		if !ok || n < minClassify || n > maxClassify {
			return Config{}, fmt.Errorf("DDOSPOT_CLASSIFY_SECONDS must be an integer from %d to %d, got %q", minClassify, maxClassify, v)
		}
		c.Classify = time.Duration(n) * time.Second
	}
	return c, nil
}

// digits parses a decimal number of digits only, without sign or spaces.
func digits(s string) (int, bool) {
	if len(s) > 4 {
		return 0, false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
	}
	n, err := strconv.Atoi(s)
	return n, err == nil
}
