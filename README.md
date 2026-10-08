# IP Scout

A Rust desktop network scanner for Windows 11, inspired by Angry IP Scanner.
This is an independent implementation with its own name and interface.

## Run on Windows 11

Download [IP Scout 0.13.0 for Windows x64](https://github.com/dducret/IP-Scout/releases/download/v0.13.0/IP-Scout-0.13.0-Windows-x64.zip),
extract the ZIP, and open `IP-Scout-0.13.0/ip-scout.exe`. Or build it from source:

```powershell
cargo run --release
```

Building requires Rust 1.88 or newer, the `x86_64-pc-windows-msvc` toolchain,
and Visual Studio Build Tools with **Desktop development with C++** and a
Windows SDK. The release app has no console window, requires no Java or .NET,
and normally runs without administrator privileges.

## Scanning

The toolbar offers **Fast** and **Deep** modes. Switching modes applies a timing
profile without changing custom TCP/UDP ports, fetchers, HTTPS policy or target range:

| Mode | Probe timeout | Max workers | Discovery window | TCP connection ceiling |
| --- | --- | --- | --- | --- |
| Fast | 200 ms | 256 | 2 seconds | Up to 1,024 local / 64 routed |
| Deep | 400 ms | 128 | 4 seconds | Up to 256 local / 32 routed |

**Adaptive concurrency** is on by default and can be disabled in Scan settings.
Max workers is an upper bound, adjustable from 1 to 256; existing saved worker
ceilings are preserved. Local host probing starts at 128 workers in Fast or 64
in Deep, then grows in steps of 32 as probes finish, respecting that ceiling.
Unused local addresses also permit growth. Purely routed scans use no more than
128 host workers, with a separate adaptive TCP budget starting at 32 in Fast or
16 in Deep and rising in steps of eight to the routed TCP ceiling.

Healthy replies allow gradual growth. Large RTT increases, a missed echo after
a successful reply, or an echo recovered during confirmation reduce the budget,
with cooldowns before further changes. Silent routed addresses are not treated
as packet loss or evidence to increase the rate. These are conservative
heuristics, not a precise measurement of tunnel capacity. Already-running work
finishes normally when the limit falls; cancellation still stops queued work.
Hover the toolbar's Auto max readout during a scan to see the current budgets.
Disabling Adaptive uses fixed limits while retaining the routed safety pacing.
Metadata and UDP retain their separate bounded pools; the adaptive controller
governs local baseline host probes, routed TCP port probes and routed echo pacing.

Addresses outside directly attached adapter subnets use routed-scan pacing,
including typical WatchGuard VPN paths. TCP/ICMP start in batches of at most eight,
at least 16 ms apart in Fast or 32 ms in Deep. Adaptive starts with 32/64 ms
intervals respectively, approaches the minimum after healthy replies and backs
off to at most 64/128 ms. This bounds bursts without relying on sub-millisecond
Windows timers. Local subnet and loopback probes are not paced.
Waiting for a pacing/connection slot does not consume the reply timeout.

After the initial sweep and fetchers, addresses without a successful echo reply
are rechecked: once in Fast, up to twice in Deep, stopping on success. Routed
confirmation uses at least 750 ms in Fast or 1,500 ms in Deep; at most 32 routed
echo requests are in flight. Local confirmation uses the configured timeout.
Recovered hosts appear immediately and receive TCP and identity fetchers. Known
responsive routed hosts also retry only inconclusive TCP ports once, retaining
open ports and avoiding re-probing confirmed refusals. A failed later probe never
erases successful evidence. The status bar shows `Rechecking current of total
addresses without an echo reply (paced confirmation)`, counting completed
addresses rather than worker indices. Updates are throttled to four per second,
with initial zero and final total always reported for an uninterrupted phase;
100% baseline coverage is not Scan complete until this work also finishes.
VPN scans can take longer than local scans. Pacing and retries reduce loss, but
cannot bypass firewall rules or guarantee discovery through a failing tunnel.

Fast enriches devices that responded to ICMP, TCP or confirmed ARP. Local
advertisements still run and can reveal additional devices. It bounds native
ARP waiting by the probe timeout, using a fixed 32-worker process-lifetime pool;
Windows calls already in progress can finish in the background, but abandoned
queued work is skipped. Deep also attempts metadata against silent addresses
and waits for native ARP confirmation. Choose Deep for slower Wi-Fi devices,
additional names and services, or longer periodic advertisement collection.
Both modes retain independently detected HTTP and HTTPS endpoints, and avoid
retrying web ports already scanned without an open TCP result.

Timing controls remain editable in Scan settings. New installations default to
Fast. Older saved configurations retain their existing timings and use Deep
until Fast is selected. The mode persists between launches and is fixed for
each running scan. It does not impose a hard five-second cutoff or mark
unfinished work as complete.

Stopping a large scan does not check the remainder of the address range.
The Scanned counter now counts completed host-discovery checks, not partially
processed rows. The stopped status shows checked/total and unchecked addresses;
fetchers may still be incomplete even when all baseline host checks finished.
Successful ping and completed TCP replies are retained when other TCP work is
cancelled. A partly checked host without a positive response is marked Incomplete,
not No response; a known-responsive host stays Alive and its details/Notes identify
incomplete discovery. Completed enrichment is retained when Stop interrupts later
work. Partial exports use `ip-scout-partial-scan.csv` as their default filename.
Only visible rows are exported; an Alive-only CSV is not evidence that every IP
in the requested range was checked. Allow a `/16` to reach Scan complete before
comparing it with a completed `/24` scan. Fast's short timeout can still miss
responses under congestion or across slower routed/VPN paths; use Deep or a
longer timeout for those networks. No mode can discover an unreachable device.

On the local `192.168.1.0/24` network, a native Windows diagnostic with the 25
fetchers available before UDP support measured 26.19 seconds. Fast took 2.76 seconds
with six common TCP ports, and 2.73 seconds with the 30-port Inventory list.
Both Fast checks found the same 34 live hosts and 33 MAC addresses as the
baseline. Fewer resolved hostnames were collected (2-3 versus 6), illustrating
the speed/completeness trade-off. These are individual LAN measurements, not a
five-second guarantee for other networks, larger port lists or custom settings.
Those measurements predate adaptive concurrency and did not include optional
UDP probes. A later baseline-only `/24` check with adaptive concurrency took
2.65 seconds and found 33 live hosts, essentially the same as fixed 128 workers
on that run. Increasing a ceiling is not a promise of a proportional speedup.

- Single IPv4 addresses: `192.168.1.10`
- Full ranges: `192.168.1.1-192.168.2.254`
- Short ranges: `192.168.1.1-254`
- CIDR subnets: `192.168.1.0/24`
- The Local menu discovers IPv4 networks from Windows adapter addresses and masks.
- TCP ports accept comma-separated values and ranges: `22,80,443,8000-8010`.
  `1-65535` scans every valid TCP port; the **All TCP** preset selects that range.
  The editor preserves compact ranges instead of expanding them into thousands
  of comma-separated values. The 1,024 Fast-mode limit is simultaneous connections,
  not the number of selectable ports. Full-port scans take substantially longer
  than scans of a small common-port list and can take minutes or longer on silent
  hosts. TCP still runs when a host does not answer ping.
  Edit them directly, use the pencil button, or select Custom in the preset menu.
  The Custom editor validates and saves the sorted, unique ports when you apply.
  The **Inventory** TCP preset selects 30 common device ports and the broader
  inventory fetcher set in one step. Custom ports can still be edited afterward.
  Ports remain editable during a scan; edits apply to the next scan, not the
  running scan's snapshot. The editor takes keyboard focus when opened.
  Clear the ports field or choose No TCP to disable TCP probes (ICMP and enabled
  local ARP discovery still run).
- Start scan launches background workers. Stop cancels remaining work and
  retains completed results. Pending TCP and DNS requests are cancelled;
  in-flight Windows ICMP calls finish within the current probe/confirmation timeout. In-flight native
  ARP confirmations finish on Windows' own retry schedule in Deep; Fast bounds
  how long a scan waits for them.
- Column headings sort results. Filters search IP, hostname, MAC, manufacturer,
  open ports, NetBIOS names, web servers, URLs, HTTP status codes,
  Bonjour, WSD, UPnP and vendor advertisements and LLMNR names.
  Select a row for details, or right-click to copy it.
- Export saves a snapshot of the currently visible results to CSV, using the
  selected fetcher columns in their configured order. IP and MAC copy buttons
  above the table copy the visible address lists, one
  address per line and in the current sort order. Missing MAC addresses are skipped.
  Small copy icons beside each IP/MAC value copy that individual address;
  missing values have a disabled button. Settings and theme persist between launches.
  Copy buttons briefly show a green check and a nearby Copied confirmation, then
  return to their normal appearance after two seconds.

## Fetchers

Open **Fetchers** in the top toolbar (or Configure in Scan settings). Select an
available fetcher and use the left arrow to add it; select a chosen fetcher and
use the right arrow to remove it. Up/down arrows arrange the selected columns.
Apply saves the selection and ordering, Cancel discards the draft, and Defaults
restores the original five fetchers. IP address and Status always remain visible.
An empty selection is valid and leaves only those two columns.

Supported fetchers: Ping, Hostname, Open TCP ports, MAC address, Manufacturer,
Refused TCP ports, ARP response, Probable brand, Notes, TTL, NetBIOS info,
Web detect, Packet loss, HTTP status, Web URL, Bonjour / mDNS, WSD info,
SSDP / UPnP, MikroTik MNDP, Ubiquiti discovery, LLMNR hostname, Service banners,
TLS certificates, Web page title, Device identity, Open UDP ports, UDP scan status,
DNS service, NTP service and SNMP info.

### Optional UDP scanning

Enable **UDP** in the toolbar to add its five fetchers, or select individual
UDP fetchers in Fetchers. UDP is off by default, leaving existing selections
unchanged. Its separate editable port field supports lists and ranges, with
Common (`53,123,161`), All UDP (`1-65535`) and custom choices. The pencil opens
the UDP editor without modifying TCP ports. Fast sends one probe per port;
Deep retries an inconclusive probe once. Neither mode silently truncates a range.

**Open UDP ports** lists ports with confirmed responses. DNS and NTP use small
protocol-specific requests; other ports get an empty datagram unless UDP 161
has an explicitly entered SNMP community. An empty datagram often gets no reply
even from an open service. **UDP scan status** shows checked/selected counts and
aggregate open, closed, open-or-filtered and error counts. No reply means
**open or filtered**, not closed. Closed is reported only when the OS explicitly
reports a refused port (including Windows' ICMP-port-unreachable socket error).
The NTP/SNMP adapters hide OS receive errors, so those failures remain inconclusive.
An invalid NTP/SNMP reply does not supply service identity or confirm an open port.

**DNS service** sends a non-recursive root SOA query to UDP 53, and shows response
code, advertised recursion, authority and a returned SOA server where available.
Request ID and question must match. This is separate from reverse hostname lookup;
it does not perform recursive external lookups, zone transfers or version queries.

**NTP service** uses a standard SNTP request on UDP 123 to collect server time,
stratum, clock offset, round-trip time and reference ID. The reply's origin and
source are validated by `sntpc`. It never changes the Windows clock or sends NTP
control/monitoring requests. A rate-limit/refusal (Kiss-of-Death) response is shown
and not retried.

**SNMP info** requires entering a community in Scan settings. Only SNMPv2c is
supported: one read-only GET requests `sysDescr.0`, `sysObjectID.0`, `sysUpTime.0`
and `sysName.0` on UDP 161. No default `public` guess, authentication guessing,
SET, walk, GETBULK or traps are used. Without a community the service fetcher shows
Not queried; selecting UDP 161 can still send a generic empty datagram.
The community field is masked, limited to 255 UTF-8 bytes, never persisted and
redacted from probe debug output. SNMPv2c sends it unencrypted on the network;
use a read-only community only on networks you administer. Responses validate
the request ID, community, version and response type through `snmp2`.
All names and descriptions remain unverified device-reported information.

UDP runs alongside other enrichment, with eight ports per host and 128 shared
scan-wide sockets. A first confirmed response is published immediately; other
updates are throttled. Stop cancels active and queued probes, retaining completed
results and marking unfinished counts incomplete. UDP probes also run against
silent hosts in Fast, but other Fast fetchers still use baseline liveness to
avoid extra work. A confirmed UDP reply can mark a host Alive. Details, filtering,
sorting and selected-column CSV include UDP data; Open ports includes TCP or UDP.
Full UDP sweeps can take a long time, especially with Deep retries and firewall
ICMP rate limiting. Prefer a small port list for quick inventory.

Additional fetchers are optional; the default selection remains unchanged.
Hover a fetcher for its details. TTL is the value in an ICMP echo reply, not an
operating-system guess, and requires no additional request. Packet loss sends
three spaced ICMP samples by default (adjustable from 1 to 10 in Scan settings)
and reports the percentage without echo replies. Ping becomes the mean of
successful replies. The details panel also shows replies versus samples.
Native ICMP API errors leave loss blank rather than being counted as packet loss.
This short sample measures ICMP responses, not reliable overall link quality.

NetBIOS info sends one unicast UDP 137 node-status query per host and lists
reported computer names, groups and service roles. It does not broadcast or log
in. Devices with NetBIOS disabled/blocked, including many phones, leave it blank.

Web detect probes HTTP/HTTPS on ports 80, 443, 8000, 8080, 8443 and 8888,
plus up to 26 additional open ports from the custom TCP list, prioritizing known
open ports within the bounded request budget. Ports already scanned without an
open result are skipped. HTTP and HTTPS are checked
independently on every candidate port, including 8080: a successful HTTP response
does not skip HTTPS, and both endpoints are retained when both succeed.
Known non-web service ports, especially printer raw TCP 9100 and LPD 515, are
excluded from generic HTTP probing to avoid submitting data to those services.
It shows the
reported Server header (for example Apache or nginx), not a verified fingerprint.
A valid response with no Server header is labeled `Server header hidden`.
HTTP status and Web URL share this same probe, without extra requests for each
selected column. HEAD requests fetch headers only, with GET fallback for 405/501;
page bodies are not downloaded unless Web page title is selected; redirects
are never followed. Environment
proxies are disabled, so probes address the target directly. No credentials are
sent. Web URL includes the actual port, and the details globe opens the first
detected endpoint.

HTTPS certificate validation is on by default. For self-signed LAN services,
Scan settings offers **Allow unverified TLS**, off by default; HTTPS results
obtained in that mode are explicitly labeled `[TLS unverified]`. All reported
names and headers should be treated as untrusted device-provided information.

### Inventory fetchers

**Service banners** reads the unsolicited greeting from open FTP, SSH, SMTP,
POP3, IMAP, VNC and eligible custom TCP services. This often exposes reported
software/version strings such as `SSH-2.0-OpenSSH_9.6`. No commands, SSH client
identification, authentication, brute force or configuration requests are sent.
Known printer/binary protocol ports are excluded. Reads stop after 1 KiB and
display at most 512 characters. At most 16 ports per host are considered.

**TLS certificates** uses Rustls and x509-parser to collect public certificate
subject/common name, issuer, DNS/IP SAN names, validity dates and serial number.
It checks common TLS ports, including 8080, and eligible confirmed custom ports.
Ports already scanned without an open result are not redundantly retried.
Certificates, including self-signed or expired ones, are captured and then the
TLS handshake is deliberately aborted: this fetcher never trusts the peer or
sends client credentials or application data. It works independently of the
Allow unverified TLS web setting. All certificate identity information is labeled
unverified, is not substituted for Hostname and is not a certificate-trust audit.
Only the leaf is parsed, with a 32 KiB limit and up to 16 SAN entries retained.
There are at most 16 endpoints and four concurrent probes per host. Banner and
certificate work shares 32 scan-wide slots, with cancellation and host deadlines.
Certificate-only enrichment overlaps hostname, UDP, NetBIOS, banner and ping
work. When web detection is selected, certificates still follow it so confirmed
custom web endpoints remain eligible. Port candidate membership uses sets to
avoid quadratic work with long open-port lists, and TLS probes share a crypto
provider while retaining separate capture verifiers for each endpoint.

**Web page title** shares the web detection probe but uses GET instead of HEAD.
Only HTML/XHTML is parsed with scraper; at most 16 KiB is retained and the body
wait is capped at 400 ms. No JavaScript, linked resources, forms, cookies,
credentials or redirects are followed. Compressed bodies are skipped. Titles
are capped at 256 characters and unverified HTTPS results are visibly labeled.
Self-signed HTTPS page titles need the existing Allow unverified TLS setting;
the certificate-only fetcher does not need that setting.

**Device identity** combines source-labeled names/models from resolved names,
NetBIOS, LLMNR, mDNS, UPnP, MikroTik/Ubiquiti, SNMP, web titles and certificate names.
It uses the other selected fetchers' results, retains conflicting names instead
of claiming certainty, and does not overwrite Hostname, MAC or IEEE Manufacturer.
At most 24 source entries are displayed. It enables hostname resolution but does
not silently enable every other protocol. All four new fetchers support sorting,
filtering, details, copying and CSV export.

Choose Inventory in the TCP preset menu for a broad scan; the Inventory button
inside Fetchers selects the same fetcher set while preserving custom ports.
Packet-loss sampling is not selected by that preset so it does not delay inventory.
Existing saved fetcher selections are preserved. Extra information may take
longer, but basic results continue to appear first. Device firewalls, missing
services, Wi-Fi isolation and privacy/randomized addresses still limit discovery.
The scanner only queries SNMP when a community is explicitly entered. It does not
use Windows credentials or router logins, and does not capture DHCP/LLDP/CDP traffic.

**Bonjour / mDNS** browses multicast DNS-SD on UDP 5353 using the Rust
`mdns-sd` library; installing Apple's Bonjour service is not required.
It shows advertised service instance names, `.local` hostnames, ports and selected
TXT properties (`model`, `ty`, `product`, `manufacturer`, `note`). Arbitrary TXT
values such as passwords/tokens are not retained. Common service types are
queried directly (AirPlay, RAOP, IPP/IPPS, printers, HTTP/HTTPS, SMB, workstation,
device info, Google Cast, SSH, VNC and scanners); a service-type enumeration query
adds other advertised types, up to 32 browses total. Up to 16 services per host
are kept. Services are matched by advertised IPv4 addresses, not by assuming the
packet sender owns every service. Bonjour data alone does not mark a host Alive:
sleep proxies can advertise services for hosts that are asleep or unreachable.

**WSD info** sends WS-Discovery probes on UDP multicast 239.255.255.250:3702
with a TTL of 1. It supports 2005 and 2009 discovery versions, querying DPWS
devices, Windows computers and ONVIF video transmitters. It shows endpoint IDs,
reported types, scopes and validated literal-IP HTTP/HTTPS transport addresses.
Replies must reference a freshly generated request ID and come from the host's
scanned IPv4 address. Up to eight endpoints per host are retained. This fetcher
does not download SOAP device metadata or open advertised URLs; WSD friendly
names, manufacturer and model are therefore not guaranteed.

**SSDP / UPnP** sends one `ssdp:all` M-SEARCH per selected interface on
239.255.255.250:1900. Responses show service/device type, USN and reported server.
When a LOCATION URL uses the replying device's literal IPv4 address, a read-only
GET can add its UPnP friendly name, manufacturer and model. Cross-host URLs,
credentials in URLs and redirects are rejected; environment proxies are disabled
and HTTPS certificates must validate. XML descriptions are limited to 16 KiB,
with DTDs and excessive depth rejected. Description fetching has a two-second
overall budget, 800 ms per request, 16 concurrent requests and at most 128 URLs.
Unreachable or unsupported descriptions leave the original SSDP details intact.
No UPnP control actions or subscriptions are sent.

**MikroTik MNDP** listens passively for UDP 5678 broadcasts and shows identity,
board/model, version, platform, interface and reported MAC. It does not modify
RouterOS settings. Advertisements are periodic: a four-second window can miss
them, so increase the Discovery window when needed. If another program owns
UDP 5678, a warning is shown instead of silently sharing the port.

**Ubiquiti discovery** sends read-only v1/v2 discovery probes to local UDP
broadcast port 10001. It shows reported name, model, platform, firmware and MAC
where available. Username, salt and authentication challenge fields are discarded.
There are no adoption, login, SSH-enable or configuration commands. Device
support and discovery settings vary by model and firmware.

**LLMNR hostname** sends one unicast TCP 5355 PTR query per on-link host, using
Hickory's DNS packet encoder/parser. Replies must match the sender, transaction,
question and answer owner. It is separate from DNS and does not overwrite the
Hostname column. LLMNR is name resolution, not service enumeration; disabled or
unsupported responders leave the column blank. IP Scout does not enable LLMNR,
change network settings, send credentials or query routed targets through LLMNR.
TCP connection setup uses TTL 1 as required by RFC 4795, and messages use DNS
TCP length framing. Unicast UDP queries, which compliant responders discard,
are not used.
This fetcher uses Rust and the native Windows socket stack; no separate software,
packet-capture driver or installation is needed. All remaining discovery fetchers
are built into the executable. LLDP/CDP and the Npcap capture integration were
removed in 0.7.1. Saved LLDP/CDP selections are discarded during upgrade without
resetting the other fetchers or scan settings.

Local advertisement fetchers are collected once before per-host probing, concurrently in a shared
four-second **Discovery window** (adjustable from 1 to 120 seconds in Scan
settings), not once per IP. A fresh discovery session is used for each scan and
Stop cancels collection. Only up to eight directly connected IPv4 interfaces
whose subnet overlaps the scan range are used; results outside the range are
discarded, and discovery is skipped with a warning when no interface overlaps.
Multicast/broadcast queries can reach other devices on those subnets even for a single-IP
scan. Up to 2,048 discovered hosts are retained to bound memory use. Unselected
fetchers add no discovery traffic or waiting time. UPnP descriptions can add up
to two seconds after that window. LLMNR runs alongside per-host NetBIOS/web work,
with a single probe-timeout deadline rather than using the discovery window.

Discovery is local-network only; it does not cross routers. Windows Firewall
may require allowing IP Scout on the private network. Guest Wi-Fi/client
isolation, multicast filtering, sleeping devices or devices that do not advertise
these protocols can leave the fields blank. The app does not change firewall
rules. Reported names, properties and scopes are unverified advertisements.

Column changes apply immediately to displayed results and exports. Changes to
probe selection take effect on the next scan; existing results are not refetched
and a running scan keeps its original options. Without a TCP or web fetcher,
TCP ports are not probed. A web fetcher also scans the custom TCP list to discover
additional candidate endpoints. Without Hostname or Probable brand, reverse DNS is skipped.
Manufacturer/Probable brand implicitly fetch MAC data even with the MAC column
hidden; Probable brand also enables reverse DNS for hostname hints. MAC address
alone skips the manufacturer database. Existing DNS/MAC preferences are migrated
when upgrading, and selections persist between launches.

ICMP remains the baseline host-discovery probe even with Ping hidden. Local ARP
discovery remains controlled by the Scan settings toggle, independently of the
ARP response column; removing that column does not disable local discovery.

## Behavior and limits

A host is **Alive** if it answers ICMP, a TCP connection succeeds or is refused,
or a fresh local ARP confirmation, NetBIOS status reply, HTTP response or
correlated WSD reply succeeds, or a valid SSDP, MNDP, Ubiquiti or LLMNR response
is received from that scanned IP, or a UDP probe gets a confirmed response.
UDP closed-port errors alone do not confirm host liveness. Bonjour alone does not confirm
IP reachability. All discovery information is unauthenticated and unverified.
**No response** means none of those probes answered; it does not prove a device
is offline. TCP errors and firewall filtering can affect discovery.

Ping uses Windows `IcmpSendEcho`. Hostnames race Windows native `GetNameInfoW`
resolution (the system cache, hosts file and configured name providers) against
DNS PTR lookup through the configured DNS servers. The first successful name wins;
an unsuccessful lookup does not discard a success from the other resolver.
This can find Windows names such as those returned by `ping -a` even when DNS
has no PTR record. Results depend on the machine's Windows name-resolution setup.
DNS uses one attempt and the probe timeout; the combined hostname deadline is
the greater of one second and the probe timeout. Stop cancels the wait.
Native calls use a process-wide pool of eight threads and an eight-request queue.
Windows calls already in progress cannot be interrupted, but they never hold up
scan completion or create additional threads; abandoned queued work is skipped.
If neither resolver finds a name before the deadline, Hostname remains blank.
NetBIOS and Bonjour remain separate optional fetchers; advertised `.local` names
are not silently used as hostnames.

Local discovery confirms ARP-only devices, including phones that ignore ping and
filter all tested TCP ports. After ping/TCP probing, on-link neighbor-cache
candidates are actively revalidated with Windows `ResolveIpNetEntry2`; a stale
cache entry alone never marks a host alive. The selected route/interface is checked
so a router's MAC is not mistaken for a remote device. This is enabled by default
and can be disabled under Local discovery. Only existing neighbor candidates are
retried, keeping unused IPs from adding an extra Windows ARP retry cycle. Devices
that have not appeared in the neighbor cache may still be missed. ARP does not
cross routers and guest Wi-Fi/client isolation can prevent local discovery.

MAC addresses are available only on directly connected networks, not loopback or
across routers. Manufacturers use bundled IEEE MA-L, MA-M and MA-S registries,
matching the most specific 24-, 28- or 36-bit assignment. This identifies the MAC
assignment holder, not necessarily the complete device's brand or model.
When no assignment is usable, explicit hostname prefixes can provide a
**Probable brand** such as `Samsung (hostname hint, unverified)`; these are hints,
not verified identity. Randomized/local MACs without a hostname hint remain
`Unknown (randomized/local MAC)` because the brand cannot be inferred from those
addresses. MAC lookup and probable-brand hints are controlled by selected fetchers.
The app does not download manufacturer data while scanning. ARP confirmation and
probable-brand fields are included in host details, copying, and CSV exports.

CIDR input excludes network/broadcast addresses for prefixes shorter than `/31`.
Explicit address ranges include their endpoints. Scans are capped at 65,536 hosts,
65,535 distinct ports per host for each of TCP and UDP, and 256 host workers. Ping and TCP run at the same
time, with up to 16 concurrent TCP probes per host and 1,024 active TCP connections
in Fast, or 256 in Deep. Timeouts apply per connection after it obtains a connection slot.
These limits keep long port lists from creating unbounded sockets. TCP scanning
still runs for hosts that do not answer ping.
Positive ping/TCP replies publish an Alive row before the complete port list has
finished. These early rows have incomplete baseline coverage: the Scanned counter
advances only after all baseline checks finish. Open-port progress is throttled
to four updates per second per host, with the first positive reply immediate.
Completed baseline ping/TCP/ARP/MAC rows then replace those provisional rows. A separate
pool of up to 32 metadata workers updates those same rows as fetchers finish;
slow metadata does not occupy the host-probe workers. Its queue is bounded at
256 hosts and applies backpressure on large scans. DNS, web, NetBIOS, LLMNR and
remaining packet-loss samples overlap rather than run in sequence. Packet-loss
sampling reuses the first ping instead of delaying the initial row.
Bonjour/WSD/SSDP/MNDP/Ubiquiti discovery runs alongside the host scan, not before
it. Its configured observation window still applies. Late discoveries update
existing rows without duplicates and hosts discovered only that way still get
their identity fetchers. Identical updates are discarded to avoid unnecessary
GUI filtering and sorting. Scan complete means all selected fetchers have finished;
while scanning, displayed details are provisional. The scanner event API emits
replacement snapshots for an IP, so consumers must upsert rather than append.
Pending updates are coalesced by IP and delivered by a separate thread; sending
to a full GUI channel no longer holds the result publisher lock or blocks a Tokio
worker. Delivery remains ordered per host and flushes before Finished, including
after cancellation. Consumers may not see every intermediate snapshot, and must
check `discovery_complete()` rather than row presence to count baseline coverage.
Optional web requests have a shared limit of 32, at most 8 per host (four HTTP/HTTPS pairs), and an
overall per-host budget of four probe timeouts, including waiting for web slots.
Completed web results are retained when that budget expires. NetBIOS has one
probe-timeout deadline. Stop cancels pending web/NetBIOS work and skips further
ICMP samples. Selecting these fetchers increases scan duration; unselected
fetchers add no network work. Only IPv4 is supported.

## Performance and structure

The GUI table remains virtualized: only visible rows are rendered. Existing-row
updates only rebuild the visible list when they can change the active filter or
sort order. Normalized search text and one selected metadata sort key per host
are cached and invalidated on updates; sorting compares cached keys instead of
formatting fetcher values for every comparison. Event ingestion has a four-ms
budget per frame, schedules another frame for bursts, and is woken by scan results
instead of relying only on the 50-ms polling fallback. This is an event-processing
budget, not a guarantee that every full-list search or sort takes four ms.

Scanning parses adapter subnet ranges once, avoids remote ARP/MAC lookups and
unused LLMNR interface selection, and reuses an ICMP handle and aligned reply
buffer per native worker. UPnP descriptions use indexed URL-to-device lookup,
including multiple services sharing one description, without changing the URL
validation, size limits, cancellation or request budgets.

An optimized-build CPU benchmark over 65,534 synthetic hosts measured metadata
sorting at 2.59 seconds with the former formatter-per-comparison approach versus
89 ms with cached keys; a repeated sort took 13 ms. A cold search took 150 ms and
a repeated cached search 1.95 ms. These measure list processing, not whole GUI
frame time or network throughput. Cold full-list queries still have a measurable
cost, and cache memory scales with the number and richness of host records.

A local baseline-only `/24` check published its first row in 16 ms, versus about
223 ms in the earlier build, and completed in 2.80 seconds with 33 live hosts.
Total duration was similar to the previous 2.65-second measurement. A WatchGuard
VPN `/24` check published its first row in 15 ms and finished in 13.12 seconds,
finding 19 live hosts including all seven previously reported addresses. These
individual runs are not speed guarantees; pacing, confirmation, timeouts and
selected fetchers still determine completion time.

`scanner.rs` now coordinates scans and re-exports the unchanged public models.
Its `scanner/` modules contain models, host enrichment, TCP/ICMP probes, scheduling
and publication, event delivery, hostname resolution and manufacturer identity.
`advertisements.rs` coordinates collection; `advertisements/` contains UDP
transport, SSDP/UPnP, vendor packet parsers and LLMNR. Tests live in separate files.
GUI filtering/sorting lives in `app/view.rs`.

## Build and verify

```powershell
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
cargo test pipeline_first_result_benchmark -- --ignored --nocapture
# Synthetic CPU benchmark; does not scan any network:
cargo test --release --bin ip-scout result_view_latency_benchmark -- --ignored --nocapture
cargo build --release --locked
.\scripts\package.ps1
```

The packaging script creates versioned `dist/IP-Scout-<version>/` and
`dist/IP-Scout-<version>-Windows-x64.zip`, leaving older running versions untouched.
The executable embeds the manufacturer database and needs no files beside it.
The benchmark uses simulated probe/metadata delays, not a LAN speed claim.
For a single-device diagnostic without advertisement collection:

```powershell
cargo run --example diagnose_host -- 192.168.1.27 --basic
```

For full-range timing comparisons using the pre-UDP fetchers (including packet loss):

```powershell
cargo run --example diagnose_scan -- 192.168.1.0/24 --fast
cargo run --example diagnose_scan -- 192.168.1.0/24 --deep
cargo run --example diagnose_scan -- 192.168.1.0/24 --fast --inventory
# Baseline + optional UDP, with all rows (including No response) and watched IPs:
cargo run --example diagnose_scan -- 192.168.213.0/24 --fast --basic --udp --csv=artifacts/diagnostic.csv --watch=192.168.213.1
# Isolate echo probing or vary concurrency/timeouts while diagnosing a VPN:
cargo run --example diagnose_scan -- 192.168.213.50 --icmp-only --timeout=1000
cargo run --example diagnose_scan -- 192.168.213.0/24 --fast --basic --workers=8 --timeout=750
# Compare against fixed concurrency (routed safety pacing still applies):
cargo run --example diagnose_scan -- 192.168.1.0/24 --fast --basic --fixed --workers=128
```

These commands scan the specified network. They report first-row, all-basic-row
and completion times, plus collected host/identity counts. The confirmation phase
is reported separately, along with changing adaptive budgets. `--fixed` disables
adaptive adjustment. `--icmp-only` runs sequential native echoes without TCP,
metadata or advertisement traffic; workers accept 1..256, timeout accepts 10..5000 ms.

For a focused HTTP/HTTPS and public certificate diagnostic on just one port:

```powershell
cargo run --example diagnose_web -- 192.168.1.1 8080
# Explicitly permit an untrusted HTTPS certificate for this read-only check:
cargo run --example diagnose_web -- 192.168.1.1 8080 --unverified-tls
```

This diagnostic uses the scanner's probes, does not follow redirects or send
credentials, and does not scan other ports or collect advertisements. Certificate
identity is always unverified; collecting it does not require the TLS opt-in.

The optional GUI smoke test opens an invisible native window, probes loopback
against a temporary TCP listener, verifies filtering/export, and writes rendered
screenshots at desktop and smaller window sizes, in light and dark themes:

```powershell
cargo run --example gui_smoke --features gui-smoke
```

Screenshots and the sample CSV are saved under `artifacts/`. This verification
does not scan the LAN or persist test settings.
It also clicks the pencil, focuses and types a custom port range, then clicks Apply
while a scan is running, and verifies validation and saving.
Clipboard checks click both list buttons and both row icons, including filtered
results, and assert the text sent to the clipboard. Unit tests cover missing MACs
and empty lists.
The GUI check also verifies that copy confirmations appear and expire.
It clicks Fast and Deep at the smaller window size, verifies each timing profile
and checks that custom ports and fetcher selections remain unchanged.
It also applies `1-65535` in the custom-port editor, verifies all 65,535 ports
are accepted, and checks that the saved text stays compact without starting a scan.
UDP checks toggle its toolbar control, apply custom and full UDP ranges without
changing TCP, and render UDP results, details and masked SNMP settings at both sizes.
Local UDP fixtures cover silence, retries, cancellation, sender filtering, DNS
correlation, NTP origin/stratum/rate-limit replies and read-only correlated SNMP.
Saved preference tests verify that SNMP communities are never persisted.
Fetcher checks click transfer/order controls, Apply and Cancel, render the dialog
in desktop light and smaller dark views, exercise empty/all selections, and
verify selected-column CSV ordering. Unit tests cover saved preferences and
metadata dependencies.
Cancellation tests retain completed open/refused TCP responses and a successful
native ping while TCP is queued. A synthetic `/16` test visits all 65,534 IPs
exactly once, including `192.168.213.1` and `192.168.212.8`, without sending LAN
traffic. GUI checks render incomplete rows, coverage and stopped-scan details.
Routed-scan tests cover per-window burst limits, pacing cancellation, recovery
after a lost echo, preserved measurement history and retrying only inconclusive
TCP ports. Cancellation while routed budgets are occupied does not send LAN traffic.
Adaptive tests cover growth, user ceilings, RTT/loss backoff, cooldowns, silent
routed addresses, waking queued work, draining reduced budgets and cancellation.
A synthetic scheduler test verifies that all 256 host workers can run together.
GUI checks render adaptive settings at both sizes and the disabled toolbar state.
Large-list GUI checks render, search and metadata-sort 65,534 synthetic hosts.
Additional regressions cover early liveness while TCP work is queued, coalesced
delivery ordering, flushing pending results after Stop, disconnected consumers,
cached-key invalidation and avoiding refreshes for unrelated row changes.
Additional tests use local HTTP and UDP fixtures for header detection, redirect
handling, NetBIOS parsing, malformed packets, deadlines and cancellation.
Bonjour tests publish real test services on an isolated loopback-only interface,
including a custom type found through service enumeration. WSD tests use local UDP fixtures and verify both namespace versions,
request IDs, address validation, deduplication, XML limits and cancellation.
GUI checks cover both discovery columns, a small dark window, the selection
dialog and selected-column CSV export. Tests do not discover services on the LAN.

An optional single-address diagnostic uses the same scanning engine:

```powershell
cargo run --example diagnose_host -- 192.168.1.106
```

A deterministic latency benchmark compares sequential and concurrent scheduling
using twelve simulated 100 ms TCP probes (not a measurement of your LAN):

```powershell
cargo test port_probe_latency_benchmark -- --ignored --nocapture
```

## Manufacturer data

`assets/oui.csv`, `assets/mam.csv`, and `assets/oui36.csv` are IEEE Registration
Authority public MA-L, MA-M and MA-S registry snapshots downloaded on 2026-10-05.
See `THIRD_PARTY_NOTICES.md`. To refresh it before rebuilding:

```powershell
Invoke-WebRequest https://standards-oui.ieee.org/oui/oui.csv -OutFile assets/oui.csv
Invoke-WebRequest https://standards-oui.ieee.org/oui28/mam.csv -OutFile assets/mam.csv
Invoke-WebRequest https://standards-oui.ieee.org/oui36/oui36.csv -OutFile assets/oui36.csv
```

Project source is MIT licensed. Third-party dependencies retain their own licenses.

