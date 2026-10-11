// Package events turns the classifications of the limiter into log lines:
// scanner events go into the log file of their pot, target events of
// sources and networks into targets.log.
package events

import (
	"encoding/base64"
	"time"

	"github.com/t3chn0m4g3/ddospot/internal/jsonlog"
	"github.com/t3chn0m4g3/ddospot/internal/limit"
)

// targets is the log file of the target events.
const targets = "targets.log"

// Files maps each pot to the log file of its scanner events.
var Files = map[limit.Proto]string{
	limit.Chargen: "chargenpot.log",
	limit.DNS:     "dnspot.log",
	limit.NTP:     "ntpot.log",
	limit.SSDP:    "ssdpot.log",
}

// Ports maps each pot to its well-known port, logged as dest_port.
var Ports = map[limit.Proto]int{
	limit.Chargen: 19,
	limit.DNS:     53,
	limit.NTP:     123,
	limit.SSDP:    1900,
}

// Logger is a limit.Observer that writes every event as one JSON line. It
// is safe for concurrent use. An event the log budget would leave out is
// counted as dropped without being built.
type Logger struct {
	w       *jsonlog.Writer
	persona string
}

// New returns a Logger writing to w; persona is the ID of the persona.
func New(w *jsonlog.Writer, persona string) *Logger {
	return &Logger{w: w, persona: persona}
}

// sampleEvent starts an event with a copy of the pot fields of s, so that
// the map shared by the snapshots of the limiter stays as it is.
func sampleEvent(s limit.Sample) map[string]any {
	ev := make(map[string]any, len(s.Fields)+16)
	for k, v := range s.Fields {
		ev[k] = v
	}
	ev["req_size"] = s.ReqSize
	ev["req_pkt"] = base64.StdEncoding.EncodeToString(s.Req)
	return ev
}

func seconds(first, last time.Time) int {
	return int(last.Sub(first) / time.Second)
}

// Scanner writes a source that stayed within its budget into the log file
// of its pot.
func (l *Logger) Scanner(s limit.Source) {
	if !l.w.Allow(Files[s.Proto]) {
		return
	}
	ev := sampleEvent(s.Sample)
	ev["time"] = jsonlog.Time(s.First)
	ev["src_ip"] = s.Addr.String()
	ev["src_port"] = s.Port
	ev["role"] = "scanner"
	ev["packets"] = s.Packets
	ev["proto"] = s.Sample.Transport
	ev["persona"] = l.persona
	ev["resp_size"] = s.Sample.RespSize
	l.w.Write(Files[s.Proto], ev)
}

func (l *Logger) target(event string, s limit.Source) map[string]any {
	ev := sampleEvent(s.Sample)
	ev["event"] = event
	ev["time"] = jsonlog.Time(s.Last)
	ev["role"] = "target"
	ev["pot"] = string(s.Proto)
	ev["dest_port"] = Ports[s.Proto]
	ev["proto"] = s.Sample.Transport
	ev["target_ip"] = s.Addr.String()
	ev["target_port"] = s.Port
	ev["persona"] = l.persona
	ev["first_seen"] = jsonlog.Time(s.First)
	ev["packets"] = s.Packets
	return ev
}

// TargetStart writes the start of a source that went beyond its budget.
func (l *Logger) TargetStart(s limit.Source) {
	if !l.w.Allow(targets) {
		return
	}
	l.w.Write(targets, l.target("attack_start", s))
}

// TargetEnd writes the end of a source announced by TargetStart.
func (l *Logger) TargetEnd(s limit.Source) {
	if !l.w.Allow(targets) {
		return
	}
	ev := l.target("attack_end", s)
	ev["last_seen"] = jsonlog.Time(s.Last)
	ev["attack_seconds"] = seconds(s.First, s.Last)
	l.w.Write(targets, ev)
}

// net starts a network event. The field sources counts the source entries
// of the network, one per address and pot.
func (l *Logger) net(event string, n limit.Net) map[string]any {
	return map[string]any{
		"event":      event,
		"time":       jsonlog.Time(n.Last),
		"role":       "target",
		"target_net": n.Prefix.String(),
		"sources":    n.Sources,
		"packets":    n.Packets,
		"first_seen": jsonlog.Time(n.First),
		"persona":    l.persona,
	}
}

// NetStart writes the start of a network that went beyond its budget.
func (l *Logger) NetStart(n limit.Net) {
	if !l.w.Allow(targets) {
		return
	}
	l.w.Write(targets, l.net("net_start", n))
}

// NetEnd writes the end of a network announced by NetStart.
func (l *Logger) NetEnd(n limit.Net) {
	if !l.w.Allow(targets) {
		return
	}
	ev := l.net("net_end", n)
	ev["last_seen"] = jsonlog.Time(n.Last)
	ev["attack_seconds"] = seconds(n.First, n.Last)
	l.w.Write(targets, ev)
}
