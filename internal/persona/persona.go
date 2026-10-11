// Package persona holds the host profiles the pots answer as and rolls the
// details of one host (name, addresses, identifiers) per start.
package persona

import (
	"fmt"
	"math/rand"
	"net/netip"
	"time"
)

// NTP is the ntpd side of a profile.
type NTP struct {
	ReadvarVersion    string // readvar "version", e.g. `ntpd 4.2.6p5@1.2349-o Tue Jun 23 15:38:18 UTC 2020 (1)`
	System, Processor string // readvar "system" and "processor"
	Stratum           uint8
	Precision         int8
	PollLog           uint8 // reftime steps every 2^PollLog s
	Monlist           bool  // mode 7 MON_GETLIST answered (ntpd < 4.2.7p26)
}

// DNS is the name server side of a profile.
type DNS struct {
	Software     string // "bind" | "dnsmasq"
	VersionBind  string // CH TXT version.bind
	HostnameBind bool   // CH TXT hostname.bind answered with the host name
	EDNSSize     uint16 // UDP size in the OPT record of an answer
}

// Device is one UPnP device with its services.
type Device struct {
	Type     string // device urn; the SSDP layer adds upnp:rootdevice for the first one
	Services []string
}

// SSDP is the UPnP side of a profile.
type SSDP struct {
	Server           string   // SERVER header
	Kind             string   // "miniupnpd" | "minidlna"
	Path             string   // path of the LOCATION URL
	PortMin, PortMax uint16   // HTTP port of the LOCATION URL
	Devices          []Device // root device first, then its embedded devices
}

// Profile is one coherent host: the versions of ntpd, the name server and
// the UPnP daemon of one distribution release.
type Profile struct {
	ID   string
	NTP  NTP
	DNS  DNS
	SSDP SSDP
}

// Persona is a profile with the details of one host.
type Persona struct {
	Profile
	Hostname            string
	LAN                 netip.Addr   // private address of the host
	RefID               netip.Addr   // upstream time server
	Peers               []netip.Addr // monlist entries besides the requester
	UUIDs               []string     // one per device
	SSDPPort            uint16
	BootID, ConfigID    uint32
	RootDelay, RootDisp float64 // seconds, base values (jitter added per answer)
}

var hostnames = []string{
	"srv01", "srv02", "srv03", "server", "server1", "nas", "nas01", "nas2",
	"media", "mediaserver", "backup", "backup2", "storage", "files", "fileserver", "home",
	"homeserver", "gateway", "gw", "router", "ns1", "ns2", "dns", "ntp",
	"time", "web01", "www", "app01", "db01", "dev", "build", "lab",
	"vm01", "vmhost", "kvm01", "docker", "plex", "pi", "office", "archive",
}

// Network interface vendor prefixes of servers and virtual machines, for
// the MAC address in the default minidlna UUID.
var macPrefixes = [][3]byte{
	{0x52, 0x54, 0x00}, // QEMU/KVM
	{0x00, 0x50, 0x56}, // VMware
	{0x00, 0x0c, 0x29}, // VMware
	{0x00, 0x15, 0x5d}, // Microsoft Hyper-V
	{0x00, 0x25, 0x90}, // Super Micro
	{0x0c, 0xc4, 0x7a}, // Super Micro
	{0xac, 0x1f, 0x6b}, // Super Micro
	{0x00, 0x1b, 0x21}, // Intel
	{0xa0, 0x36, 0x9f}, // Intel
}

// Roll picks a profile and rolls the details of the host.
func Roll(r *rand.Rand) Persona {
	cat := Catalog()
	p := Persona{Profile: cat[r.Intn(len(cat))]}
	p.Hostname = hostnames[r.Intn(len(hostnames))]
	p.LAN = rollLAN(r)

	upstream := serversOfStratum(p.NTP.Stratum - 1)
	p.RefID = upstream[r.Intn(len(upstream))]
	p.Peers = rollPeers(r, p.LAN, p.RefID)

	switch p.SSDP.Kind {
	case "minidlna":
		// minidlna's default uuid: "MiniDLNA" in hex, then the MAC address.
		pre := macPrefixes[r.Intn(len(macPrefixes))]
		p.UUIDs = []string{fmt.Sprintf("4d696e69-444c-164e-9d41-%02x%02x%02x%02x%02x%02x",
			pre[0], pre[1], pre[2], r.Intn(256), r.Intn(256), r.Intn(256))}
	default:
		// miniupnpd: the root uuid from uuidgen, each embedded device one
		// step further in the last hex digit (complete_uuidvalues).
		u := uuid4(r)
		for range p.SSDP.Devices {
			p.UUIDs = append(p.UUIDs, u)
			u = nextUUID(u)
		}
	}
	p.SSDPPort = p.SSDP.PortMin + uint16(r.Intn(int(p.SSDP.PortMax-p.SSDP.PortMin)+1))

	up := 86400 + r.Int63n(89*86400+1)
	p.BootID = uint32(time.Now().Unix() - up)
	p.ConfigID = uint32(1 + r.Intn(16777215))
	p.RootDelay = 0.005 + r.Float64()*0.075
	p.RootDisp = 0.01 + r.Float64()*0.11
	return p
}

func rollLAN(r *rand.Rand) netip.Addr {
	last := byte(2 + r.Intn(249))
	if r.Intn(2) == 0 {
		return netip.AddrFrom4([4]byte{192, 168, byte(r.Intn(256)), last})
	}
	return netip.AddrFrom4([4]byte{10, byte(r.Intn(256)), byte(r.Intn(256)), last})
}

// rollPeers returns 3-9 addresses: the upstream server, up to two more
// time servers and clients of the host's /24.
func rollPeers(r *rand.Rand, lan, ref netip.Addr) []netip.Addr {
	n := 3 + r.Intn(7)
	remote := 1 + r.Intn(min(3, n-1))
	seen := map[netip.Addr]bool{lan: true, ref: true}
	peers := []netip.Addr{ref}
	for len(peers) < remote {
		a := timeServers[r.Intn(len(timeServers))].addr
		if !seen[a] {
			seen[a] = true
			peers = append(peers, a)
		}
	}
	b := lan.As4()
	for len(peers) < n {
		b[3] = byte(2 + r.Intn(249))
		a := netip.AddrFrom4(b)
		if !seen[a] {
			seen[a] = true
			peers = append(peers, a)
		}
	}
	r.Shuffle(len(peers), func(i, j int) { peers[i], peers[j] = peers[j], peers[i] })
	return peers
}

func serversOfStratum(s uint8) []netip.Addr {
	var out []netip.Addr
	for _, t := range timeServers {
		if t.stratum == s {
			out = append(out, t.addr)
		}
	}
	return out
}

// uuid4 returns a random version 4 UUID in lower case.
func uuid4(r *rand.Rand) string {
	var b [16]byte
	for i := range b {
		b[i] = byte(r.Intn(256))
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// nextUUID steps the last hex digit as miniupnpd does: 9 to a, f to 0,
// any other digit to the next one.
func nextUUID(u string) string {
	b := []byte(u)
	switch c := &b[len(b)-1]; *c {
	case '9':
		*c = 'a'
	case 'f':
		*c = '0'
	default:
		*c++
	}
	return string(b)
}
