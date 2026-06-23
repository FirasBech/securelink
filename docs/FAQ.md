# SecureLink FAQ

Short answers to common questions. For the full guide, see the
[User Manual](MANUAL.md).

### Is my data actually encrypted?

Yes. Every session does an ephemeral X25519 key exchange, derives a key with
HKDF-SHA256, and encrypts each chunk with AES-256-GCM. An HMAC and a per-session
sequence number reject tampered, replayed, or reordered packets. Session keys
are never written to disk.

### What's the difference between LAN, VLAN, and WAN?

- **LAN** — both machines on the same local network; direct TCP, peers found
  automatically via mDNS.
- **VLAN** — same idea, but transfers are also checked against per-VLAN policy
  rules.
- **WAN** — across networks or the internet; uses a reliable-UDP transport that
  recovers from packet loss and reordering.

The app auto-selects a mode, or you can force one.

### How do I send a file to someone?

Both sides run SecureLink. The receiver clicks **Start Listening** (or runs
`recv`); the sender chooses the file and the receiver's IP/port and clicks
**Send File** (or runs `send <file> <ip>`). On the same LAN, the sender can pick
the receiver from the *Devices on Your Network* list instead of typing the address.

### Where are received files saved?

Wherever you set **Save to** in the *Receive a File* panel (or `--output-dir` on
the CLI). The default is the current folder.

### What does "Trust this device?" / "Allow unknown devices" mean?

The first time you exchange with a device, SecureLink records its identity
fingerprint (Trust On First Use). After that, connections are silent, and a
*changed* fingerprint is refused — protecting against impersonation. On the CLI
you're prompted to confirm the first time; in the GUI (which has no console for a
prompt) you tick **Allow unknown devices** for that first contact.

### Can I transfer over the internet?

Two ways:

- **Over a VPN (easiest).** If both machines are on the same VPN — Tailscale,
  WireGuard, etc. — they see each other on a stable private link, so SecureLink
  uses **direct TCP** and skips NAT traversal entirely. Just use the peer's VPN
  address (the *Receive a File* panel's **Your address** shows yours). Tailscale's
  `100.64.x` range is auto-detected as VPN mode; WireGuard's private IPs route as
  LAN over the tunnel. This is the most reliable path today.
- **Plain WAN.** Works **if the receiver's UDP port is reachable** (e.g.
  port-forwarded). Fully automatic NAT traversal — STUN discovery, a rendezvous
  to exchange endpoints, and UDP hole punching — is implemented in `core/nat.py`
  (`wan_connect`) but is not yet wired into the one-click send/receive flow, and
  there is no relay for symmetric NATs.

### Do I need to open ports or change my firewall?

For LAN/VLAN, usually no (same network). To **receive** from another network you
need that port reachable through your router/firewall (default 55000). The sender
needs no inbound ports.

### Where are my keys and logs stored?

Under `~/.securelink/`: your device key (`identity_ed25519.pem`), trusted peers
(`known_hosts.json`), counters (`session.json`), and daily logs
(`logs/<date>.json`). The CLI `--state-dir` flag relocates this folder.

### What are the alerts in the dashboard?

Passive security observations from the Scapy guards: ARP-table changes
(spoofing, HIGH), TTL drops (possible interception, MEDIUM), and VLAN-policy
violations (HIGH). They require packet-capture privileges; without them, no such
events are generated and transfers still work.

### Does it work on macOS / Linux?

The core, CLI, and dashboard are pure Python and run anywhere PyQt5 does. The
double-click launchers and shortcuts are Windows-specific; elsewhere use
`python -m ui.dashboard` and `python -m ui.cli`.

### Is this production-ready?

No — it's a learning/portfolio prototype. It implements real cryptography and a
real reliable-UDP transport, but it has not been security-audited, the WAN path
is only loopback-tested (not across real NATs), and VLAN support is policy
enforcement rather than tagged-frame generation. See the README's *Known
Limitations*.

### My antivirus flagged it / packet capture doesn't work.

The security guards use Scapy, which needs a packet-capture driver (Npcap on
Windows) and elevated privileges. That capability sometimes trips antivirus
heuristics. The guards are optional — file transfer works without them, just
without the ARP/TTL/VLAN alerts.

### The shortcut icon didn't update.

Windows caches shortcut icons. Sign out and back in (or restart Explorer) to
force a refresh. The icon always shows correctly inside the running app.
