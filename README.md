# IP Scout

IP Scout is a native desktop application for scanning IPv4 networks and collecting
device and service information. Windows 11 is supported; the initial Linux x64
port supports X11 and Wayland with the platform limits described below.

## Download and run

Download [IP Scout 0.15.0 for Windows x64](https://github.com/dducret/IP-Scout/releases/download/v0.15.0/IP-Scout-0.15.0-Windows-x64.zip),
extract the ZIP, and run `IP-Scout-0.15.0/ip-scout.exe`.

The application is portable and normally runs without administrator privileges.
It requires no Java, .NET, or packet-capture driver. Release notes, source code,
and a SHA-256 checksum are available on the
[release page](https://github.com/dducret/IP-Scout/releases/tag/v0.15.0).

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
| Multiple targets | `192.168.1.0/24, 10.0.0.5` |
| Exclusions | `192.168.1.0/24 !192.168.1.20-30` |

Use **Tools → Targets** to paste a multiline list or import a UTF-8 text/CSV
file. CSV imports use an explicit IP/address/target column, so exported result
files can be scanned again. Duplicates are merged; exclusions apply to scanning
and discovery. The combined limit is 65,536 selected addresses after exclusions.
Excluded CIDRs remove their whole subnet, including boundary addresses.

Ctrl-click result rows to select several devices, then use **Scan selected**
in Tools or the row context menu. **Scan visible results** respects the current
filter; **Retry inconclusive** scans no-response or unfinished rows. These actions
start a new scan of those addresses and replace the result table.

**Tools → Profiles** saves named target, port, fetcher and scan settings between
sessions. SNMP communities are excluded from saved profiles.

**Tools → History** saves and reloads JSON scan snapshots, including actual target
coverage, selected probes and completion status. Select a saved baseline or use
the current results as the baseline, then compare the next scan. Differences
include newly/lost responses, changed identities, observed ports and service
information. Comparisons use common target/probe coverage; incomplete or changed
discovery settings are reported as uncertain. A missing response does not prove
that a device is offline or that a port is closed. Snapshot files are limited to
128 MiB; import and comparison run in the background. SNMP communities are not
recorded.

TCP and UDP port fields accept lists and ranges, such as `22,80,443,8000-8010`.
Scan settings control timeouts, concurrency, local discovery, and HTTPS policy.
Changes to scanning options apply to the next scan.

### Interface language

Open **Scan settings** (the gear button), then **Interface language**, and choose
**Automatic (system)**, **English**, or **Français**. The choice takes effect
immediately, including during a scan, and is saved between launches. Automatic
is the default for new and existing installations. It follows `LC_ALL`,
`LC_MESSAGES`, or `LANG` when explicitly set; on Windows, neutral `C`/`POSIX`
locales do not override the preferred Windows display languages. Unsupported
languages fall back to English.

Language is an application preference, separate from scan profiles. CSV column
names and values, JSON scan histories, comparison data, and observed device
names remain independent of the interface language. Technical details returned
by probes, the engine or the operating system retain their original text.

With **Adaptive** enabled in Scan settings, ICMP and TCP deadlines learn each
host's latency and jitter independently. Unmeasured hosts keep the configured
initial timeout; shortening requires at least three replies. Learned deadlines
are bounded at 50 ms on local networks or 100 ms on routed networks, and at up
to four times the initial timeout, capped at five seconds. Confirmation probes
keep a separate timing history. Turning Adaptive off uses fixed probe timeouts.

When a usable hostname is discovered, web and TLS fetchers also check that name
using HTTP Host and TLS SNI while connecting to the scanned IP. IP-based results
are retained, and hostname-specific certificate results show the SNI name.
The HTTPS verification setting applies to both kinds of web requests.

The **Service details** fetcher identifies SSH, FTP, SMTP, POP3, IMAP and VNC from
greetings, and uses bounded read-only SMB2 negotiation, RTSP OPTIONS and Redis
PING on their conventional ports. It also includes HTTP/HTTPS observations.
Each record shows its protocol evidence and labels server product claims as
unverified. It sends no authentication or generic printer/unknown-port payloads.
**Network path** shows the Windows-selected interface, source IP and next hop.
Routed TCP/ICMP pacing adapts separately by interface/next hop, while shared
connection ceilings remain in effect.

## Features

- ICMP ping, TCP port scanning, and local ARP discovery.
- Hostnames, MAC addresses, and manufacturer lookup using bundled IEEE registries.
- Optional UDP probes, including DNS, NTP, and read-only SNMPv2c queries.
- Local discovery through Bonjour/mDNS, WSD, SSDP/UPnP, MikroTik MNDP,
  Ubiquiti discovery, and LLMNR.
- HTTP/HTTPS detection, web page titles, service banners, TLS certificate details,
  and combined device identity information.
- Configurable result columns, search, sorting, IP/MAC copying, and CSV export.
- Target lists and exclusions, saved scan profiles, and rescanning selected results.
- Scan history snapshots and comparisons, protocol service details, and network path information.

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

Windows builds embed `assets/ip-scout.ico` in the executable for Explorer and
shortcut icons. After changing the source logo PNG, run
`.\scripts\create-icon.ps1` to regenerate its 16–256 pixel icon variants before
building. The icon file is included in the repository; ordinary builds need no
image conversion step.

Builds generate compact embedded resources automatically in Cargo's `OUT_DIR`.
The IEEE CSV snapshots remain the source of truth: every 24-, 28- and 36-bit
assignment and organization name is stored in a compressed binary table, while
unused registry/address columns are omitted. The table is decompressed once,
on the first manufacturer lookup, and requires no network or external data file.
The window icon and toolbar logo reuse the existing transparent 256-pixel PNG
frame from `assets/ip-scout.ico`; the full-resolution source PNG stays available
for future icon generation. Normal builds require only the existing Rust tools.

To compare two builds using the same compiler and release options, keep the first
executable before rebuilding, then run:

```powershell
python scripts/measure-size.py --before artifacts/size-baseline/ip-scout.exe --after target/x86_64-pc-windows-msvc/release/ip-scout.exe --output artifacts/size-comparison.json
```

The report includes exact byte counts and SHA-256 hashes, plus executable-only
ZIP sizes with identical names, timestamps and compression settings. These ZIP
measurements are independent of the release package and its documentation.

To verify the language picker using native screenshots and simulated clicks,
without network probes:

```powershell
cargo run --locked --example gui_smoke --features gui-smoke -- --language-only
```

Screenshots are written to `artifacts/i18n-*.png`.

### Linux x64

On Debian/Ubuntu, install Rust with rustup and the native build dependencies:

```sh
sudo apt-get update
sudo apt-get install -y build-essential pkg-config libx11-dev libxcursor-dev libxi-dev libxrandr-dev libxinerama-dev libxkbcommon-dev libxkbcommon-x11-dev libwayland-dev libegl1-mesa-dev libgl1-mesa-dev
cargo run --release --locked
```

Use `bash scripts/package-linux.sh` to create a `.tar.gz` archive and a separate
Linux SHA-256 checksum file in `dist/`. Extract it and run `./ip-scout` inside the
package directory. It is a native GNU/Linux x64 binary using the system's glibc,
OpenGL, X11/Wayland and libxkbcommon libraries, rather than a fully static or
AppImage build. File dialogs use the desktop's XDG portal; install
`xdg-desktop-portal` and its GNOME/KDE/GTK backend if the desktop does not already
provide one.

The initial port supports TCP/UDP probes, DNS names, native ICMP with latency and
TTL, local IPv4 interface selection, service/device discovery, exports and scan
histories. ICMP uses Linux ping sockets, without a raw-socket fallback or running
the application as root. The user's group must be allowed by
`net.ipv4.ping_group_range`; restricted systems report an ICMP error, while TCP
and the other probes remain usable. No system network settings are changed by
the application.

Fresh ARP confirmation, MAC/manufacturer discovery from the neighbor table,
per-interface route inspection and native NSS hostname fallback are not ported
yet. DNS PTR lookup and ordinary local multicast discovery still work. New
Linux preferences omit MAC/manufacturer collection and ARP confirmation, and
unavailable collectors cannot be newly selected in the collector picker. Old
profiles and histories remain readable, including their stored MAC, manufacturer
and route values. Route-based pacing shares a conservative fallback budget.

To exercise the native UI on a headless Linux machine:

```sh
sudo apt-get install -y xvfb xauth dbus-x11
cargo build --locked --example gui_smoke --features gui-smoke
LIBGL_ALWAYS_SOFTWARE=1 WINIT_UNIX_BACKEND=x11 dbus-run-session -- xvfb-run -a -s '-screen 0 1280x1024x24' env -u WAYLAND_DISPLAY -u WAYLAND_SOCKET target/debug/examples/gui_smoke --language-only
```

### GitHub Actions

`.github/workflows/build.yml` runs on pushes, pull requests and manual dispatch.
Its Windows x64 and Linux x64 jobs check formatting, run Clippy and tests, build
release packages with `--locked`, and upload their archives and SHA-256 checksums
as workflow artifacts. Linux also runs the language-picker UI smoke test under
Xvfb with software OpenGL and uploads its screenshots. No GitHub Release is
published by this workflow, and no signing or publishing secret is required.

Linux CI uses Ubuntu 22.04 to keep the build-host glibc baseline at 2.35; a locally
built archive inherits the libc requirements of its own build environment.
macOS, ARM64, AppImage and distro-specific installers are not included yet.

## License

Project source is licensed under the [MIT license](LICENSE). Third-party
libraries and the bundled IEEE manufacturer data are described in
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
