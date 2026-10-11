package persona

import (
	"math/rand"
	"net/netip"
	"regexp"
	"strings"
	"testing"
	"time"
)

func countDevices(d []Device) int { return len(d) }

func TestRollIsCoherent(t *testing.T) {
	for seed := int64(0); seed < 500; seed++ {
		p := Roll(rand.New(rand.NewSource(seed)))
		if !p.LAN.IsPrivate() {
			t.Fatalf("%d: LAN %s", seed, p.LAN)
		}
		if p.RefID.IsPrivate() || !p.RefID.Is4() {
			t.Fatalf("%d: refid %s", seed, p.RefID)
		}
		if len(p.UUIDs) != countDevices(p.SSDP.Devices) {
			t.Fatalf("%d: uuids", seed)
		}
		if p.NTP.Monlist != strings.HasPrefix(p.NTP.ReadvarVersion, "ntpd 4.2.6") {
			t.Fatalf("%d: monlist vs version", seed)
		}
		if p.SSDPPort < p.SSDP.PortMin || p.SSDPPort > p.SSDP.PortMax {
			t.Fatalf("%d: port", seed)
		}
	}
}

func TestRollVaries(t *testing.T) {
	a, b := Roll(rand.New(rand.NewSource(1))), Roll(rand.New(rand.NewSource(2)))
	if a.UUIDs[0] == b.UUIDs[0] || a.LAN == b.LAN {
		t.Fatal("two rolls share details")
	}
}

func TestEveryProfileIsPicked(t *testing.T) {
	seen := map[string]bool{}
	for s := int64(0); s < 200; s++ {
		seen[Roll(rand.New(rand.NewSource(s))).ID] = true
	}
	if len(seen) != len(Catalog()) {
		t.Fatalf("picked %v", seen)
	}
}

func TestRollIsDeterministic(t *testing.T) {
	a, b := Roll(rand.New(rand.NewSource(7))), Roll(rand.New(rand.NewSource(7)))
	if a.ID != b.ID || a.Hostname != b.Hostname || a.LAN != b.LAN || a.RefID != b.RefID ||
		strings.Join(a.UUIDs, ",") != strings.Join(b.UUIDs, ",") || a.ConfigID != b.ConfigID {
		t.Fatal("same seed, different persona")
	}
}

func TestCatalogProfiles(t *testing.T) {
	ids := map[string]bool{}
	for _, p := range Catalog() {
		if ids[p.ID] {
			t.Fatalf("duplicate id %s", p.ID)
		}
		ids[p.ID] = true
		if !strings.HasPrefix(p.NTP.ReadvarVersion, "ntpd 4.2.") || !strings.HasSuffix(p.NTP.ReadvarVersion, " (1)") {
			t.Errorf("%s: version %q", p.ID, p.NTP.ReadvarVersion)
		}
		if !strings.HasPrefix(p.NTP.System, "Linux/") || p.NTP.Processor != "x86_64" {
			t.Errorf("%s: system %q processor %q", p.ID, p.NTP.System, p.NTP.Processor)
		}
		if p.NTP.Stratum < 2 || p.NTP.Stratum > 3 || p.NTP.Precision > -18 || p.NTP.Precision < -26 || p.NTP.PollLog < 6 || p.NTP.PollLog > 10 {
			t.Errorf("%s: ntp values %+v", p.ID, p.NTP)
		}
		switch p.DNS.Software {
		case "bind":
			if !strings.Contains(p.DNS.VersionBind, "-RedHat-") || !p.DNS.HostnameBind {
				t.Errorf("%s: bind %+v", p.ID, p.DNS)
			}
		case "dnsmasq":
			if !strings.HasPrefix(p.DNS.VersionBind, "dnsmasq-2.") || p.DNS.HostnameBind {
				t.Errorf("%s: dnsmasq %+v", p.ID, p.DNS)
			}
		default:
			t.Errorf("%s: software %q", p.ID, p.DNS.Software)
		}
		if p.DNS.EDNSSize < 512 {
			t.Errorf("%s: edns %d", p.ID, p.DNS.EDNSSize)
		}
		switch p.SSDP.Kind {
		case "minidlna":
			if !strings.Contains(p.SSDP.Server, " DLNADOC/1.50 UPnP/1.0 MiniDLNA/1.") || p.SSDP.PortMin != 8200 || p.SSDP.PortMax != 8200 {
				t.Errorf("%s: minidlna %+v", p.ID, p.SSDP)
			}
		case "miniupnpd":
			if !strings.Contains(p.SSDP.Server, " MiniUPnPd/2.") || p.SSDP.PortMin >= p.SSDP.PortMax {
				t.Errorf("%s: miniupnpd %+v", p.ID, p.SSDP)
			}
		default:
			t.Errorf("%s: kind %q", p.ID, p.SSDP.Kind)
		}
		if p.SSDP.Path != "/rootDesc.xml" || len(p.SSDP.Devices) == 0 {
			t.Errorf("%s: path %q devices %d", p.ID, p.SSDP.Path, len(p.SSDP.Devices))
		}
		for _, d := range p.SSDP.Devices {
			if !strings.HasPrefix(d.Type, "urn:schemas-upnp-org:device:") || len(d.Services) == 0 {
				t.Errorf("%s: device %+v", p.ID, d)
			}
			for _, s := range d.Services {
				if !strings.HasPrefix(s, "urn:") || !strings.Contains(s, ":service:") {
					t.Errorf("%s: service %q", p.ID, s)
				}
			}
		}
	}
	if len(ids) != 4 {
		t.Fatalf("profiles %v", ids)
	}
}

func TestCatalogReturnsCopies(t *testing.T) {
	c := Catalog()
	c[0].SSDP.Devices[0].Services[0] = "changed"
	c[0].SSDP.Devices = nil
	if d := Catalog()[0].SSDP.Devices; len(d) == 0 || d[0].Services[0] == "changed" {
		t.Fatal("catalog shares its slices")
	}
}

func TestTimeServers(t *testing.T) {
	if len(timeServers) < 60 {
		t.Fatalf("%d time servers", len(timeServers))
	}
	doc := []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("198.51.100.0/24"),
		netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("100.64.0.0/10")}
	seen := map[netip.Addr]bool{}
	for _, s := range timeServers {
		a := s.addr
		if !a.Is4() || !a.IsGlobalUnicast() || a.IsPrivate() || a.IsLoopback() {
			t.Errorf("%s is no public IPv4 address", a)
		}
		for _, p := range doc {
			if p.Contains(a) {
				t.Errorf("%s in %s", a, p)
			}
		}
		if s.stratum != 1 && s.stratum != 2 {
			t.Errorf("%s: stratum %d", a, s.stratum)
		}
		if seen[a] {
			t.Errorf("%s twice", a)
		}
		seen[a] = true
	}
}

func stratumOf(a netip.Addr) uint8 {
	for _, s := range timeServers {
		if s.addr == a {
			return s.stratum
		}
	}
	return 0
}

func TestRefIDIsOneStratumUp(t *testing.T) {
	for seed := int64(0); seed < 300; seed++ {
		p := Roll(rand.New(rand.NewSource(seed)))
		if got := stratumOf(p.RefID); got == 0 || got != p.NTP.Stratum-1 {
			t.Fatalf("%d: refid %s stratum %d, persona stratum %d", seed, p.RefID, got, p.NTP.Stratum)
		}
	}
}

func TestRolledDetails(t *testing.T) {
	v4 := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	dlna := regexp.MustCompile(`^4d696e69-444c-164e-9d41-[0-9a-f]{12}$`)
	lan10, lan192 := netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("192.168.0.0/16")
	hosts := map[string]bool{}
	for _, h := range hostnames {
		hosts[h] = true
	}
	if len(hosts) != 40 {
		t.Fatalf("%d distinct host names", len(hosts))
	}
	now := time.Now().Unix()
	for seed := int64(0); seed < 500; seed++ {
		p := Roll(rand.New(rand.NewSource(seed)))
		if !hosts[p.Hostname] {
			t.Fatalf("%d: host name %q", seed, p.Hostname)
		}
		if !lan10.Contains(p.LAN) && !lan192.Contains(p.LAN) {
			t.Fatalf("%d: LAN %s", seed, p.LAN)
		}
		if last := p.LAN.As4()[3]; last < 2 || last > 250 {
			t.Fatalf("%d: LAN %s", seed, p.LAN)
		}
		lanNet, _ := p.LAN.Prefix(24)
		var local, remote int
		seen := map[netip.Addr]bool{p.LAN: true}
		for _, a := range p.Peers {
			if seen[a] {
				t.Fatalf("%d: peer %s twice or LAN", seed, a)
			}
			seen[a] = true
			switch {
			case lanNet.Contains(a):
				if last := a.As4()[3]; last < 2 || last > 250 {
					t.Fatalf("%d: peer %s", seed, a)
				}
				local++
			case stratumOf(a) != 0:
				remote++
			default:
				t.Fatalf("%d: peer %s neither LAN nor time server", seed, a)
			}
		}
		if n := len(p.Peers); n < 3 || n > 9 || remote < 1 || remote > 3 || local < 1 {
			t.Fatalf("%d: peers %v", seed, p.Peers)
		}
		switch p.SSDP.Kind {
		case "minidlna":
			if len(p.UUIDs) != 1 || !dlna.MatchString(p.UUIDs[0]) || p.SSDPPort != p.SSDP.PortMin {
				t.Fatalf("%d: minidlna %v port %d", seed, p.UUIDs, p.SSDPPort)
			}
		case "miniupnpd":
			if !v4.MatchString(p.UUIDs[0]) {
				t.Fatalf("%d: uuid %s", seed, p.UUIDs[0])
			}
			for i := 1; i < len(p.UUIDs); i++ {
				if p.UUIDs[i] != nextUUID(p.UUIDs[i-1]) {
					t.Fatalf("%d: uuids %v", seed, p.UUIDs)
				}
			}
		}
		if up := now - int64(p.BootID); up < 86400-5 || up > 90*86400+5 {
			t.Fatalf("%d: boot %d s ago", seed, up)
		}
		if p.ConfigID < 1 || p.ConfigID > 16777215 {
			t.Fatalf("%d: config id %d", seed, p.ConfigID)
		}
		if p.RootDelay < 0.005 || p.RootDelay > 0.08 || p.RootDisp < 0.01 || p.RootDisp > 0.12 {
			t.Fatalf("%d: root delay %f disp %f", seed, p.RootDelay, p.RootDisp)
		}
	}
}

func TestNextUUID(t *testing.T) {
	for in, want := range map[string]string{
		"4a6c1e9e-0d1b-4f43-9c4e-2b8f0a7d3c11": "4a6c1e9e-0d1b-4f43-9c4e-2b8f0a7d3c12",
		"4a6c1e9e-0d1b-4f43-9c4e-2b8f0a7d3c19": "4a6c1e9e-0d1b-4f43-9c4e-2b8f0a7d3c1a",
		"4a6c1e9e-0d1b-4f43-9c4e-2b8f0a7d3c1f": "4a6c1e9e-0d1b-4f43-9c4e-2b8f0a7d3c10",
	} {
		if got := nextUUID(in); got != want {
			t.Errorf("nextUUID(%s) = %s, want %s", in, got, want)
		}
	}
}
