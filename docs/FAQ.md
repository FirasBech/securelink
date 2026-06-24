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
- **Coordination server (through NATs).** STUN discovery, NAT-type detection
  (`natcheck`), a rendezvous to exchange endpoints, UDP hole punching, and a
  TURN-style relay fallback (`RelayServer`) for symmetric NATs. You host the
  servers yourself (`python -m ui.cli rendezvous` / `relay`), point SecureLink at
  them on the **Settings** tab, then transfer by entering the same **Internet
  token** on both sides — in the dashboard's Send/Receive tabs (Advanced
  options) or via `wansend` / `wanrecv` on the CLI.

- **Plain WAN.** Also works **if the receiver's UDP port is reachable** (e.g.
  port-forwarded) — tick **WAN** and use the address directly, no server needed.

### Does SecureLink use anyone's server? Do I have to trust a third party?

No. SecureLink **bundles no server** and phones home to nothing. LAN, VLAN, and
VPN transfers are fully peer-to-peer. For internet (WAN) transfers through NATs
you *may* optionally use a coordination server — but **you bring your own**: host
the `rendezvous` (and, for symmetric NATs, `relay`) commands on a machine you
control, then point SecureLink at them with `settings --rendezvous host:port`
(or the dashboard's Settings tab). Leave them unset and you simply don't use
coordination — VPN remains the easiest internet path. (STUN, used only to learn
your public address, defaults to Google's public servers and is overridable.)

### Do I need a Tailscale account to use VPN mode?

Yes — Tailscale is a separate product with its own sign-in. **Each user installs
Tailscale and runs `tailscale up` once** to log in to their tailnet; SecureLink
can't do that for you (it never sees your Tailscale credentials). Once you're
signed in, SecureLink reads `tailscale status` to list your tailnet peers and
detect your `100.x` address. If Tailscale is installed but you're not signed in,
the dashboard shows a reminder to run `tailscale up`. (WireGuard works too — set
up the tunnel yourself, then just use the peer's tunnel IP; no SecureLink
integration needed.)

### Do I need to open ports or change my firewall?

For LAN/VLAN, usually no (same network). To **receive** from another network you
need that port reachable through your router/firewall (default 55000). The sender
needs no inbound ports. Over a VPN you don't need to open anything — the VPN
carries the connection.

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
