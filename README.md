# IP Scout

IP Scout is a native Windows 11 desktop application for scanning IPv4 networks
and collecting device and service information.

## Download and run

Download [IP Scout 0.13.0 for Windows x64](https://github.com/dducret/IP-Scout/releases/download/v0.13.0/IP-Scout-0.13.0-Windows-x64.zip),
extract the ZIP, and run `IP-Scout-0.13.0/ip-scout.exe`.

The application is portable and normally runs without administrator privileges.
It requires no Java, .NET, or packet-capture driver. Release notes, source code,
and a SHA-256 checksum are available on the
[release page](https://github.com/dducret/IP-Scout/releases/tag/v0.13.0).

## Usage

1. Enter an IPv4 address, range, or subnet, or select a network from **Local**.
2. Choose **Fast** for shorter timeouts or **Deep** for longer timeouts and
   metadata collection against addresses that did not respond initially.
3. Select TCP ports and configure the information to collect in **Fetchers**.
   Enable **UDP** if needed; it is off by default.
4. Click **Start scan**. Results appear as probes complete. **Stop** cancels
   remaining work and retains completed results.
5. Filter or sort the results, select a device for details, or export the visible
   rows to CSV.

Accepted targets:

| Format | Example |
| --- | --- |
| Single address | `192.168.1.10` |
| Address range | `192.168.1.1-192.168.2.254` |
| Short range | `192.168.1.1-254` |
| CIDR subnet | `192.168.1.0/24` |

TCP and UDP port fields accept lists and ranges, such as `22,80,443,8000-8010`.
Scan settings control timeouts, concurrency, local discovery, and HTTPS policy.
Changes to scanning options apply to the next scan.

## Features

- ICMP ping, TCP port scanning, and local ARP discovery.
- Hostnames, MAC addresses, and manufacturer lookup using bundled IEEE registries.
- Optional UDP probes, including DNS, NTP, and read-only SNMPv2c queries.
- Local discovery through Bonjour/mDNS, WSD, SSDP/UPnP, MikroTik MNDP,
  Ubiquiti discovery, and LLMNR.
- HTTP/HTTPS detection, web page titles, service banners, TLS certificate details,
  and combined device identity information.
- Configurable result columns, search, sorting, IP/MAC copying, and CSV export.

## Limits and result interpretation

- IPv4 only, with a maximum of 65,536 addresses per scan.
- **No response** means the selected probes received no response; it does not
  establish that a device is offline. Firewalls, VPNs, isolation, and timeouts
  can limit discovery.
- MAC addresses and local discovery depend on directly connected networks.
  Manufacturer lookup identifies the MAC assignment holder; reported names,
  brands, and device identities are unverified.
- UDP silence is reported as **open or filtered**. SNMP information requires an
  explicitly entered community, which is not saved and is sent unencrypted by
  SNMPv2c.
- Results remain provisional until **Scan complete**. Stopped scans can contain
  incomplete hosts and unchecked addresses. CSV exports include only visible rows.

## Build from source

Requires Rust 1.88 or newer, the `x86_64-pc-windows-msvc` toolchain, and Visual
Studio Build Tools with **Desktop development with C++** and a Windows SDK.

```powershell
git clone https://github.com/dducret/IP-Scout.git
cd IP-Scout
cargo run --release --locked
```

To create a Windows x64 ZIP, run `.\scripts\package.ps1`. Output is saved in `dist/`.

## License

Project source is licensed under the [MIT license](LICENSE). Third-party
libraries and the bundled IEEE manufacturer data are described in
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
