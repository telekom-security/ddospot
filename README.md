# ddospot

ddospot is a honeypot for UDP reflection attacks. It offers four services
that answer on UDP and records who sends them requests:

| Service | Port | Answers as |
|---------|------|------------|
| CHARGEN | 19/udp | a character generator (RFC 864) |
| DNS | 53/udp, 53/tcp | the name server of the host profile, recursive through Quad9 |
| NTP | 123/udp | the ntpd of the host profile |
| SSDP | 1900/udp | the UPnP daemon of the host profile (MiniUPnPd or MiniDLNA) |

ddospot is a single static Go binary. It writes JSON lines into five log
files and is configured through three environment variables.

## How reflection works

UDP has no handshake. A server that receives a UDP request sends its answer
to the source address written in the packet, and it cannot tell whether that
address is the real sender. In a reflection attack the sender writes the
address of the victim as the source of its requests and sends them to many
servers. The servers answer the victim, which then receives traffic it never
asked for, from servers it does not know. Services whose answers are larger
than the requests make this worse for the victim.

For a honeypot this means: the source address of such requests is not the
attacker, it is the target of the attack. ddospot records these addresses as
targets and keeps its own answers to them within a small budget.

## Roles: scanners and targets

ddospot sorts every source into one of two roles:

- **Scanner**: a host that sends a few requests from its real address, for
  example a research project or someone looking for such services. Scanners
  get answers and are written into the log file of the service:
  `chargenpot.log`, `dnspot.log`, `ntpot.log` or `ssdpot.log`, with `src_ip`
  and `role` `scanner`.
- **Target**: the forged source of an attack. Its requests come in large
  numbers, so it soon goes beyond its budget. Targets are written into
  `targets.log` with `target_ip` and `role` `target`.

A new source is held for 60 seconds (`DDOSPOT_CLASSIFY_SECONDS`) before
ddospot decides. During the hold it gets answers within its budget. A source
that stays within its budget until the hold ends is a scanner, and one line
with its first request is written for it. A source that sends more packets
than its budget, during the hold or later, is a target: `targets.log` gets
an `attack_start` line, and an `attack_end` line once the source has been
quiet for 10 minutes. The same happens for networks with `net_start` and
`net_end`. Sources of DNS over TCP are never targets (see below).

## Response budgets

Every request is counted against these budgets:

| Budget | Default |
|--------|---------|
| per source address and service | the first 5 packets may be answered |
| per network (IPv4 /24, IPv6 /48), across all services | the first 20 packets may be answered |
| all answers together | 50 answers and 64 KiB per second |

- The source and network budgets count packets, whether they were answered
  or not. A packet within these budgets is answered only if the budget for
  all answers together has room for its answer.
- The sixth packet of a source makes it a target; from then on it gets no
  more answers from that service.
- Requests without an answer count as well, for example an NTP mode the
  persona does not answer, or an SSDP request without the headers the
  daemon needs.
- The 21st packet of a network blocks the network: none of its addresses
  gets no answer over UDP from any service. Sources in such a
  network are not written as scanners, except sources of DNS over TCP
  (see below).
- The state of a source or a network lasts until it has sent no packet for
  10 minutes; every packet starts the 10 minutes again. Then it is removed,
  and a target gets its end line.
- A scanner that comes back after that starts with a full budget and gets
  answers again. Hosts that check a service now and then send a few packets
  each time and see a working service each time.
- The tables hold at most 200000 sources and 200000 networks. When they are
  full, new sources get no answer until entries expire. Full tables take up
  to about 300 MiB of memory.

### DNS over TCP

A TCP connection starts with a handshake, so the source address of a query
over TCP is the address of the sender. ddospot counts these queries apart
from those over UDP:

- A source gets answers to its first 5 queries over TCP; further queries
  get no answer until the source has been quiet for 10 minutes.
- A source over TCP is never a target, and its queries are not counted for
  its network. It also gets its answers when its network is blocked, and
  it is written as a scanner there too.
- The budget for all answers together applies to UDP only.
- Queries over TCP that go to Quad9 have an upstream share of their own,
  2 queries per second with a burst of 5, within the rate limit of all
  queries to Quad9. A query beyond that share gets SERVFAIL.
- At most 256 TCP connections are open at a time, 4 of them from one
  address. Further connections are closed right after they are accepted.

## Services

### CHARGEN

Every datagram is answered with one datagram of lines of printable
characters, each line starting one character further along than the line
before, as RFC 864 describes.

### DNS

DNS answers on UDP and TCP port 53.

- **Recursion.** Questions of class IN are resolved through Quad9
  (`9.9.9.9` and `149.112.112.112`) over DNS over TLS. This needs outgoing
  connections to port 853/tcp. The certificate of `dns.quad9.net` is checked
  against the CA bundle of the image, with TLS 1.2 or later. Answers are
  cached, and the queries to Quad9 have a rate limit of their own, 10 per
  second with a burst of 20; questions over TCP have a smaller share within
  it. A question Quad9 does not answer in time, or that is over the rate
  limit, gets SERVFAIL, over UDP and over TCP.
- **Health of the upstream.** ddospot asks Quad9 once a minute while it
  answers, and every 10 seconds while it does not. Until the first of these
  probes succeeds, and after three failed probes in a row, questions of
  class IN are answered with REFUSED. Each change is printed on stdout.
- **`DDOSPOT_DNS_RECURSION=off`** turns recursion off; questions of class IN
  are then always answered with REFUSED.
- **CHAOS class.** `version.bind` is answered with the version string of the
  persona's name server, also with recursion off; BIND personas also answer
  `hostname.bind` with the host name.
- **ANY** questions of class IN are answered with a single HINFO record,
  as RFC 8482 describes, while recursion is on and Quad9 answers; otherwise
  they get REFUSED like the other questions of class IN.
- **Answer size.** UDP answers are kept small: an answer that does not fit
  the UDP size of the request (the plain DNS size, or the EDNS size the
  client offers, within a limit) is sent with the truncation flag and without
  records. The client can then ask again over TCP and gets the complete
  answer there.

### NTP

NTP answers as the ntpd of the persona:

- mode 3 (client) requests with a server answer: stratum, reference server,
  precision and timestamps of the persona;
- mode 6 READVAR requests for the system variables, with the version,
  system and processor strings of the persona;
- mode 7 requests for the monitor list only on personas with ntpd 4.2.6
  (`centos6`, `centos7`); the other personas do not answer mode 7.

Other requests get no answer.

### SSDP

SSDP answers M-SEARCH requests as the UPnP daemon of the persona: MiniUPnPd
with the devices of an internet gateway, or MiniDLNA with a media server.
The headers, the order of the answers and the wait before them are those of
the daemon and its version. Requests that are not M-SEARCH, or that lack
the headers the daemon needs, get no answer.

## Personas

At every start ddospot picks one host profile and answers as that host on
all four services. A profile is one release of a Linux distribution with
the versions of its ntpd, name server and UPnP daemon:

| ID | Distribution | NTP | DNS | SSDP |
|----|--------------|-----|-----|------|
| `centos6` | CentOS 6.10 | ntpd 4.2.6p5 | BIND 9.8.2 | MiniDLNA 1.1.5 |
| `centos7` | CentOS 7.9 | ntpd 4.2.6p5 | BIND 9.11.4 | MiniDLNA 1.3.0 |
| `debian11` | Debian 11 | ntpd 4.2.8p15 | dnsmasq 2.85 | MiniUPnPd 2.2.1 |
| `ubuntu2004` | Ubuntu 20.04 | ntpd 4.2.8p12 | dnsmasq 2.90 | MiniDLNA 1.2.1 |

The details of the host are rolled per start: host name, private LAN
address, NTP reference server and peers, UPnP UUIDs, the HTTP port of the
UPnP description, boot time, and the root delay and dispersion of NTP. The
persona of a run is printed at the start and written into every log line
(`persona`).

## Log files

All log files are in `DDOSPOT_LOG_DIR` (default `/var/log/ddospot`). Each
line is one JSON object. Files are opened in append mode, so log rotation
with `copytruncate` works. Times are UTC in the form
`YYYY-MM-DD HH:MM:SS.ffffff`. At most 200 lines per second are written
for the four scanner files together (burst 400) and 200 for `targets.log`
(burst 2000); ddospot prints the number of lines left out once a minute on
stdout.

### Scanner lines

`chargenpot.log`, `dnspot.log`, `ntpot.log` and `ssdpot.log` get one line
per scanner and service, with the first request of the source:

| Field | Content |
|-------|---------|
| `time` | time of the first packet |
| `role` | `scanner` |
| `src_ip`, `src_port` | address and port of the source |
| `proto` | `udp`, or `tcp` for DNS over TCP |
| `verified` | true only for DNS over TCP, where the source completed a handshake; UDP sources are not verified, because UDP source addresses can be forged |
| `packets` | packets of the source to this service so far |
| `req_size` | size of the first request in bytes |
| `req_pkt` | the first request, base64, at most its first 512 bytes; DNS: the request as parsed and packed again |
| `resp_size` | size of the answer to the first request; for a DNS question that goes to Quad9 the largest answer its transport allows |
| `persona` | ID of the persona |

Fields of the service, taken from the first request:

| Service | Fields |
|---------|--------|
| CHARGEN | none |
| DNS | `opcode`; with a question also `dns_name`, `dns_type`, `dns_cls` |
| NTP | `mode`: `DATA` (client), `CONTROL` (mode 6), `MONLIST` (mode 7) or `OTHER` (any other mode, or a datagram too short to tell) |
| SSDP | `st` (search target), `mx` (the MX header as sent), each cut to 256 bytes |

### Target lines

`targets.log` gets the start and the end of every target, for single
addresses and for networks.

`attack_start` and `attack_end` are written for one target address on one
service:

| Field | Content |
|-------|---------|
| `event` | `attack_start` or `attack_end` |
| `time` | time of the last packet so far |
| `role` | `target` |
| `target_ip`, `target_port` | source address and port of the requests, that is the target |
| `pot` | `chargen`, `dns`, `ntp` or `ssdp` |
| `dest_port` | port of the service: 19, 53, 123 or 1900 |
| `proto` | `udp` |
| `packets` | packets from the target to this service so far |
| `first_seen` | time of the first packet |
| `last_seen` | time of the last packet (`attack_end` only) |
| `attack_seconds` | seconds from the first to the last packet (`attack_end` only) |
| `req_size`, `req_pkt` | the first request, as in the scanner lines |
| `persona` | ID of the persona |

The fields of the service (see above) are added as well.

`net_start` and `net_end` are written for a blocked network:

| Field | Content |
|-------|---------|
| `event` | `net_start` or `net_end` |
| `time` | time of the last packet so far |
| `role` | `target` |
| `target_net` | the network, e.g. `192.0.2.0/24` |
| `sources` | number of source entries in the network, one per address and service |
| `packets` | packets from the network to all services so far |
| `first_seen` | time of the first packet |
| `last_seen` | time of the last packet (`net_end` only) |
| `attack_seconds` | seconds from the first to the last packet (`net_end` only) |
| `persona` | ID of the persona |

When ddospot stops, it writes the end lines of all open targets and the
scanner lines of the sources still in their hold.

### Standard output

ddospot prints `ddospot v<version> persona=<id>` at the start, and once a
minute the number of log lines left out by the line budget or lost to write
errors, when there were any. With recursion on it prints a line for every
change of the health of Quad9:

```
dns upstream: answering, class IN resolved
dns upstream: not answering (<last error>), class IN answered with REFUSED
```

## Settings

| Variable | Values | Default |
|----------|--------|---------|
| `DDOSPOT_LOG_DIR` | folder of the log files | `/var/log/ddospot` |
| `DDOSPOT_DNS_RECURSION` | `on` or `off` | `on` |
| `DDOSPOT_CLASSIFY_SECONDS` | hold of a new source in seconds, integer from 1 to 600 | `60` |

A value outside these rules stops ddospot at the start with an error
message and exit code 1. The services listen on their standard ports on all
addresses.

## Running it

The image is built `FROM scratch` and contains only the binary, a CA
bundle and an empty log folder owned by uid 2000. It runs as uid and gid 2000, works with a read-only root file
system, writes its logs to `/var/log/ddospot` and stops within 2 seconds on
SIGTERM.

```sh
docker build -t ddospot .
docker run -d --name ddospot --read-only \
  -v ddospot_log:/var/log/ddospot \
  -p 19:19/udp -p 53:53/udp -p 53:53/tcp -p 123:123/udp -p 1900:1900/udp \
  ddospot
```

`docker-compose.yml` does the same with compose: `docker compose up -d
--build`. A bind mount for the logs needs a folder that uid 2000 can write
to.

The services use ports below 1024 inside the container. Docker allows this
for unprivileged users by default; on a runtime that does not, the container
needs `NET_BIND_SERVICE` or other ports.

## Operator note

Projects that scan the internet record services like these and may list the
address of the host as offering them. Hosting providers sometimes receive
such lists and ask the owner of the address about it. Run ddospot on an
address where you can answer such questions, and tell your provider about
the honeypot if your contract asks for it.

## Build and test

Go 1.26 or later.

| Command | What it does |
|---------|--------------|
| `make test` | `go test ./...` |
| `make vet` | `go vet ./...` |
| `make fuzz` | runs every fuzz test of the CHARGEN, DNS, NTP and SSDP packages for 60 seconds each |
| `make build` | static binary in `bin/ddospot` |
| `docker build -t ddospot .` | image; the build runs the tests first |

The Dockerfile cross-compiles on the build platform, so
`docker buildx build --platform linux/amd64,linux/arm64 .` works without
emulating Go.

## License and origin

MIT, see [LICENSE](LICENSE). ddospot is based on
[aelth/ddospot](https://github.com/aelth/ddospot) by aelth, also under the
MIT license.
