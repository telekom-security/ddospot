package persona

const (
	urnDevice  = "urn:schemas-upnp-org:device:"
	urnService = "urn:schemas-upnp-org:service:"
)

// minidlnaDevices is the MediaServer of minidlna 1.x (minissdp.c
// known_service_types).
func minidlnaDevices() []Device {
	return []Device{{
		Type: urnDevice + "MediaServer:1",
		Services: []string{
			urnService + "ContentDirectory:1",
			urnService + "ConnectionManager:1",
			"urn:microsoft.com:service:X_MS_MediaReceiverRegistrar:1",
		},
	}}
}

// miniupnpdIGD2Devices is the device tree of miniupnpd 2.2.1 built as
// Debian does (configure --igd2 --ipv6, WANPPPConnection advertised):
// minissdp.c known_service_types under IGD_V2.
func miniupnpdIGD2Devices() []Device {
	return []Device{
		{Type: urnDevice + "InternetGatewayDevice:2", Services: []string{
			urnService + "Layer3Forwarding:1",
			urnService + "DeviceProtection:1",
		}},
		{Type: urnDevice + "WANDevice:2", Services: []string{
			urnService + "WANCommonInterfaceConfig:1",
		}},
		{Type: urnDevice + "WANConnectionDevice:2", Services: []string{
			urnService + "WANIPConnection:2",
			urnService + "WANIPv6FirewallControl:1",
			urnService + "WANPPPConnection:1",
		}},
	}
}

// Catalog returns the profiles. Each call builds new values, callers may
// change them.
func Catalog() []Profile {
	return []Profile{
		// CentOS 6.10, last updates (vault.centos.org/6.10/updates/x86_64):
		// ntp-4.2.6p5-15.el6.centos.x86_64.rpm, usr/sbin/ntpd;
		// bind-9.8.2-0.68.rc1.el6_10.8.x86_64.rpm, usr/sbin/named (built-in
		// max-udp-size 4096); kernel-2.6.32-754.35.1.el6.x86_64.rpm.
		// minidlna 1.1.5 (sourceforge.net/projects/minidlna, minidlna-1.1.5.tar.gz)
		// built on the host: configure takes OS_VERSION from uname -r,
		// upnphttp.h MINIDLNA_SERVER_STRING, port 8200 of minidlna.conf.
		{
			ID: "centos6",
			NTP: NTP{
				ReadvarVersion: "ntpd 4.2.6p5@1.2349-o Wed Dec 19 20:22:34 UTC 2018 (1)",
				System:         "Linux/2.6.32-754.35.1.el6.x86_64",
				Processor:      "x86_64",
				Stratum:        3, Precision: -23, PollLog: 10, Monlist: true,
			},
			DNS: DNS{Software: "bind", VersionBind: "9.8.2rc1-RedHat-9.8.2-0.68.rc1.el6_10.8", HostnameBind: true, EDNSSize: 4096},
			SSDP: SSDP{
				Server: "2.6.32-754.35.1.el6.x86_64 DLNADOC/1.50 UPnP/1.0 MiniDLNA/1.1.5",
				Kind:   "minidlna", Path: "/rootDesc.xml", PortMin: 8200, PortMax: 8200,
				Devices: minidlnaDevices(),
			},
		},
		// CentOS 7.9.2009, last updates (vault.centos.org/7.9.2009):
		// os/x86_64 ntp-4.2.6p5-29.el7.centos.2.x86_64.rpm, usr/sbin/ntpd;
		// updates/x86_64 bind-9.11.4-26.P2.el7_9.16.x86_64.rpm, usr/sbin/named
		// (built-in max-udp-size 4096); kernel-3.10.0-1160.119.1.el7.x86_64.rpm.
		// minidlna 1.3.0 (minidlna-1.3.0.tar.gz, as in RPM Fusion
		// minidlna-1.3.0-4.el8.src.rpm) built on the host, OS_VERSION = uname -r.
		{
			ID: "centos7",
			NTP: NTP{
				ReadvarVersion: "ntpd 4.2.6p5@1.2349-o Tue Jun 23 15:38:18 UTC 2020 (1)",
				System:         "Linux/3.10.0-1160.119.1.el7.x86_64",
				Processor:      "x86_64",
				Stratum:        2, Precision: -24, PollLog: 10, Monlist: true,
			},
			DNS: DNS{Software: "bind", VersionBind: "9.11.4-P2-RedHat-9.11.4-26.P2.el7_9.16", HostnameBind: true, EDNSSize: 4096},
			SSDP: SSDP{
				Server: "3.10.0-1160.119.1.el7.x86_64 DLNADOC/1.50 UPnP/1.0 MiniDLNA/1.3.0",
				Kind:   "minidlna", Path: "/rootDesc.xml", PortMin: 8200, PortMax: 8200,
				Devices: minidlnaDevices(),
			},
		},
		// Debian 11 bullseye, last packages (deb.debian.org,
		// archive.debian.org/debian-security): ntp_4.2.8p15+dfsg-1_amd64.deb,
		// usr/sbin/ntpd; dnsmasq-base_2.85-1+deb11u2_amd64.deb, usr/sbin/dnsmasq
		// (default EDNS size 1232 since deb11u1); miniupnpd-iptables_2.2.1-1_amd64.deb,
		// usr/sbin/miniupnpd (OS_VERSION from the build host's /etc/debian_version,
		// IGD v2, http_port 0: a port of the kernel's ip_local_port_range);
		// linux-image-5.10.0-46-amd64_5.10.262-1_amd64.deb.
		{
			ID: "debian11",
			NTP: NTP{
				ReadvarVersion: "ntpd 4.2.8p15@1.3728-o Wed Sep 23 11:46:38 UTC 2020 (1)",
				System:         "Linux/5.10.0-46-amd64",
				Processor:      "x86_64",
				Stratum:        2, Precision: -23, PollLog: 10, Monlist: false,
			},
			DNS: DNS{Software: "dnsmasq", VersionBind: "dnsmasq-2.85", HostnameBind: false, EDNSSize: 1232},
			SSDP: SSDP{
				Server: "Debian/bullseye/sid UPnP/1.1 MiniUPnPd/2.2.1",
				Kind:   "miniupnpd", Path: "/rootDesc.xml", PortMin: 32768, PortMax: 60999,
				Devices: miniupnpdIGD2Devices(),
			},
		},
		// Ubuntu 20.04 focal with focal-updates (archive.ubuntu.com):
		// universe ntp_4.2.8p12+dfsg-3ubuntu4.20.04.1_amd64.deb, usr/sbin/ntpd
		// (built without a date); main dnsmasq-base_2.90-0ubuntu0.20.04.1_amd64.deb,
		// usr/sbin/dnsmasq (default EDNS size 1232); universe
		// minidlna_1.2.1+dfsg-1ubuntu0.20.04.2_amd64.deb, usr/sbin/minidlnad;
		// linux-image-5.4.0-216-generic_5.4.0-216.236_amd64.deb.
		{
			ID: "ubuntu2004",
			NTP: NTP{
				ReadvarVersion: "ntpd 4.2.8p12@1.3728-o (1)",
				System:         "Linux/5.4.0-216-generic",
				Processor:      "x86_64",
				Stratum:        3, Precision: -24, PollLog: 10, Monlist: false,
			},
			DNS: DNS{Software: "dnsmasq", VersionBind: "dnsmasq-2.90", HostnameBind: false, EDNSSize: 1232},
			SSDP: SSDP{
				Server: "Ubuntu DLNADOC/1.50 UPnP/1.0 MiniDLNA/1.2.1",
				Kind:   "minidlna", Path: "/rootDesc.xml", PortMin: 8200, PortMax: 8200,
				Devices: minidlnaDevices(),
			},
		},
	}
}
