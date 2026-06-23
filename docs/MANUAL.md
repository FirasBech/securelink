# SecureLink User Manual

A practical guide to installing, launching, and using SecureLink. For the
shorter overview and architecture, see the [README](../README.md); for quick
answers, see the [FAQ](FAQ.md).

---

## 1. Install

SecureLink needs **Python 3.11+** and five packages:

```bash
pip install "cryptography>=42" "scapy>=2.5" "zeroconf>=0.132" "PyQt5>=5.15" "pytest>=8"
```

- `cryptography` — the encryption and key exchange
- `scapy` — packet capture for the security guards (optional at runtime)
- `zeroconf` — mDNS peer discovery on the LAN
- `PyQt5` — the dashboard GUI
- `pytest` — the test suite (not needed to run the app)

---

## 2. Launching

**Dashboard (GUI):**

- Windows: just double-click **`SecureLink.bat`** in the project folder, or use
  the Desktop / Start Menu **SecureLink Dashboard** shortcut. No terminal needed.
- Any OS: `python -m ui.dashboard`

**Command line:** `python -m ui.cli <command>` (see section 5).

---

## 3. Key concepts

### Transfer modes

| Mode | When to use it | How it moves data |
| --- | --- | --- |
| **LAN** | Both machines on the same local network | Direct TCP; peers found via mDNS |
| **VLAN** | Segmented enterprise network with VLAN policy | TCP, checked against `config/vlan_policy.json` |
| **VPN** | Both machines on the same VPN (Tailscale, WireGuard…) | Direct TCP over the VPN link — no NAT traversal needed |
| **WAN** | Across networks / the internet, no shared VPN | Reliable UDP (handles loss and reordering) |

The dashboard and CLI pick a mode automatically (a VLAN id → VLAN, a Tailscale /
CGNAT `100.64.0.0/10` peer → VPN, any other public IP → WAN, otherwise LAN), or
you can force one with `--wan` / the mode selector. WireGuard/OpenVPN peers use
private IPs (`10.x` / `192.168.x`), so they already route as LAN over the tunnel.

### Identity and trust

- Each installation has an **Ed25519 device key** generated on first run and
  stored at `~/.securelink/identity_ed25519.pem`. Its SHA-256 **fingerprint**
  identifies your device to peers.
- **Trust On First Use (TOFU):** the first time you exchange with a device, its
  fingerprint is recorded in `~/.securelink/known_hosts.json`. Future sessions
  with that device are silent. If a device's key ever changes, the connection is
  refused — that is the protection against impersonation.

### Encryption

Every transfer session:

1. does an ephemeral **X25519** key exchange and derives a session key with
   **HKDF-SHA256** (salted by both sides' random nonces);
2. encrypts each chunk with **AES-256-GCM**;
3. protects each chunk with an **HMAC-SHA256** and a **sequence number**, so
   tampering and replayed/duplicated packets are rejected.

Keys are ephemeral per session — they are not written to disk.

### Where things live

Everything per-user is under `~/.securelink/`:

- `identity_ed25519.pem` / `.pub` — your device key
- `known_hosts.json` — fingerprints you have trusted
- `session.json` — running byte/chunk/alert counters (the `status` command)
- `logs/<date>.json` — one JSON event per line

(The CLI `--state-dir DIR` flag relocates this whole folder, e.g. for testing.)

---

## 4. Using the dashboard

![The SecureLink dashboard](screenshots/dashboard.png)

The window has a **Send a File** and **Receive a File** panel on the left, and
the **Devices on Your Network**, **Activity Log**, and **Security Alerts**
panels on the right. Each input has a tooltip — hover over it for a plain-English
explanation.

### Send a file

1. **Send a File → File:** click *Browse* and choose a file.
2. **Device / Address:** pick a discovered device from the dropdown / *Devices on
   Your Network* list, or type the address and port directly.
3. **Mode:** leave on *Auto*, or force *LAN / VLAN / VPN / WAN*.
4. The first time you send to a new device, tick **Allow unknown devices** (the
   GUI has no console for the interactive trust prompt — ticking this records the
   peer's fingerprint and proceeds).
5. Click **Send File.** The progress bar shows percent, bytes, and live
   throughput; the status line confirms when it finishes.

### Receive a file

1. **Receive a File → Port:** the port to listen on (default 55000).
2. **Save to:** the download directory (*Browse* to pick one).
3. Optionally set an **Allowlist** (comma-separated IPs/CIDRs) and tick **WAN**
   for reliable-UDP transfers or **Allow unknown devices** for a first contact.
4. **Your address** lists the IPs this machine is reachable on, labelled
   LAN / VPN / public — hand one to the sender (prefer the VPN address if you
   share a VPN). It refreshes with **Refresh Peers**.
5. Click **Start Listening.** The button becomes **Stop**; the status shows
   "Listening…" then "Received …" when a file arrives. Each start handles one
   incoming transfer.

### Monitor

- **Devices on Your Network** lists LAN peers found via mDNS — and, if the
  Tailscale CLI is installed, your tailnet peers too (the **Source** column reads
  `mdns` or `tailscale`). Click one to fill the send fields. Tailscale peers
  assume the default port, since Tailscale can't know if/where SecureLink is
  listening — adjust the port if needed. Tailscale requires its own sign-in: each
  user runs `tailscale up` once. If it's installed but you're not signed in, an
  amber reminder appears here.
- **Activity Log** shows every event; use the filter box and **Alerts only**
  toggle to narrow it. The summary reads "shown / total events".
- **Security Alerts** panel lists security alerts, color-coded by severity (HIGH = red,
  MEDIUM = amber).

---

## 5. Command-line reference

Entry point: `python -m ui.cli <command>`. `--state-dir DIR` works on every
command.

| Command | What it does |
| --- | --- |
| `send <file> <peer>` | Send a file. Flags: `--vlan N`, `--wan`, `--port`, `--mtu`, `--allow-unknown` |
| `recv` | Listen for one incoming file. Flags: `--port`, `--wan`, `--output-dir`, `--allowlist`, `--vlan`, `--allow-unknown` |
| `scan` | Discover LAN peers via mDNS (`--timeout`) |
| `logs` | Print today's security log (`--tail N`, `--alerts-only`) |
| `status` | Show running transfer counters |
| `stun` | Print this host's public IP:port via STUN (`--stun-host`, `--stun-port`) |

Examples:

```bash
# Send over LAN
python -m ui.cli send report.pdf 192.168.1.10

# Send over a VLAN-scoped path
python -m ui.cli send report.pdf 192.168.1.50 --vlan 30

# Send over WAN (reliable UDP), skipping the trust prompt
python -m ui.cli send report.pdf 203.0.113.10 --wan --port 55000 --allow-unknown

# Receive into a folder, restricted to one subnet
python -m ui.cli recv --port 55000 --output-dir ./inbox --allowlist 192.168.1.0/24

# Find peers, see this host's public endpoint, view alerts
python -m ui.cli scan
python -m ui.cli stun
python -m ui.cli logs --alerts-only
```

---

## 6. Security monitoring

When run with packet-capture privileges, the guards watch traffic and write
findings to the JSON log (and the dashboard's Security Alerts panel):

- **ARP guard** — flags a host whose MAC address changes (possible ARP
  spoofing). Severity HIGH.
- **TTL guard** — flags a sudden TTL drop from a peer (a possible extra hop /
  interception). Severity MEDIUM.
- **VLAN guard** — flags traffic that violates `config/vlan_policy.json`
  (deny-by-default source→destination rules). Severity HIGH.

The guards degrade gracefully: without Scapy or capture privileges they simply
do not produce these events, and transfers still work.

---

## 7. Troubleshooting

| Symptom | Likely cause / fix |
| --- | --- |
| Transfer fails immediately in the GUI on a new peer | Tick **Allow unknown devices** the first time (no console for the trust prompt). |
| `Connection refused` when sending | The receiver isn't listening, wrong IP/port, or a firewall is blocking the port. |
| `address already in use` when receiving | Another process holds that port; pick a different `--port`. |
| Device doesn't appear in *Devices on Your Network* | mDNS may be blocked on the network; type the IP and port manually. |
| WAN transfer to an internet peer times out | The receiver's UDP port must be reachable (port-forwarded). NAT hole punching is available programmatically (`core.nat.wan_connect`) but not yet wired into the one-click send. |
| No ARP/TTL/VLAN alerts ever appear | Packet capture needs admin/root (and Npcap on Windows); without it the guards stay quiet by design. |
| Shortcut still shows the old/default icon | Windows caches icons — sign out and back in, or restart Explorer. |
| "A device's key changed" / connection refused | TOFU protection: the peer's identity key differs from what's stored. If legitimate (reinstall), remove its entry from `~/.securelink/known_hosts.json`. |

---

See the [FAQ](FAQ.md) for shorter answers to common questions.
