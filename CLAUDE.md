# CLAUDE.md

Guidance for working in the SecureLink codebase.

## What this is

SecureLink is a security-focused Python file-transfer prototype for LAN / VLAN
(and, on the roadmap, WAN) environments. It demonstrates authenticated
encryption, signed device identity, a custom encrypted wire format, passive
network monitoring, and JSON audit logging. It is a portfolio/demo project, not
a production tool.

Not a git repository (yet). Windows-first (`Path.home()` is used for state),
but the code is OS-agnostic.

## Run / test

```bash
pip install -r requirements.txt

pytest tests/ -q              # full suite — currently 27 tests
python -m core.crypto         # crypto self-test
python -m core.capsule        # capsule self-test
python -m ui.cli send <file> <peer>   # CLI entrypoint
python -m ui.dashboard        # PyQt5 GUI
```

Per-user state lives under `~/.securelink/`: `identity_ed25519.pem`,
`known_hosts.json`, `session.json`, and `logs/<date>.json`. The CLI's
`--state-dir` flag (on every subcommand) redirects that root to a chosen
directory — used by `tests/test_cli.py` to keep tests out of the real home.

## Architecture

Three layers, strict one-directional dependency: `ui` → `core` + `security`.

### `core/` — transfer engine

- **crypto.py** — X25519 ephemeral DH, HKDF-SHA256 key derivation,
  AES-256-GCM per-chunk encryption, HMAC-SHA256 helpers. Every failure raises
  `CryptoError`. `KeyExchange` is single-use (a second `derive()` raises).
- **capsule.py** — the "GRE capsule" wire format and `SequenceTracker`
  (replay/ordering defense with a sliding window). See wire format below.
- **auth.py** — Ed25519 device identity, fingerprinting (SHA-256 of the raw
  public key), Trust-On-First-Use via `known_hosts.json`.
- **transport.py** — orchestration + the shared `FrameChannel` abstraction.
  Signed handshake (each side sends identity pubkey + ephemeral pubkey + nonce +
  Ed25519 signature; session salt is derived from both nonces) then a
  length-framed capsule stream. `stream_send`/`stream_receive` run over any
  channel; `_StreamChannel` is the TCP one. **Do not duplicate the handshake** —
  add a channel, not a parallel handshake.
- **udp_transport.py** — WAN mode. `ReliableUdpChannel` is a Go-Back-N windowed
  ARQ `FrameChannel` over UDP (cumulative ACKs, up to `DEFAULT_WINDOW` frames in
  flight), so it reuses `stream_send`/`stream_receive` verbatim. Single-threaded:
  every `_pump` processes both ACKs and DATA, so the window self-heals across the
  handshake's request/response turns. `stream_send` calls `flush()` to drain the
  window before close; the receiver then `linger()`s to re-ACK retransmits —
  required to recover a dropped final ACK. Verified under 25% bidirectional loss
  by `tests/test_udp_reliability.py`; touch that test if you change the ARQ.
- **stun.py** — RFC 8489 STUN client. The message codec is pure/offline-testable;
  only `discover_public_endpoint` touches the network.
- **discovery.py** — mDNS announce/scan (zeroconf). `auto_select_transport_mode`
  returns `"vlan"` if a vlan_id is set, else `"lan"`.

### `security/` — passive monitoring

All scapy-based and degrade gracefully when scapy is missing (imports guarded,
guards return `None`). `capture.py` ties `ArpGuard`, `TtlGuard`, and
`VlanPolicyEngine` together and emits `SecurityEvent`s to `JsonEventLogger`.

### `ui/`

- **cli.py** — argparse: `send`, `recv`, `scan`, `logs`, `status`.
- **dashboard.py** — PyQt5 GUI; reads the same JSON logs. Tests run it offscreen.

## Capsule wire format (big-endian)

```text
GRE header   8 bytes   flags(0x2000) · protocol(0x0800) · chunk_id(u32)
HMAC-SHA256  32 bytes  over (header + nonce + ciphertext)
AES-GCM nonce 12 bytes random per chunk
ciphertext   N bytes   AES-256-GCM, 16-byte tag appended
```

52-byte fixed prefix. HMAC is verified before decryption (encrypt-then-MAC).

## Conventions

- `from __future__ import annotations` at the top of every module; PEP 604
  unions (`int | None`).
- Each layer defines its own exception type (`CryptoError`, `CapsuleError`,
  `TransportError`, `TrustDecisionError`) and wraps lower-level failures in it.
- Tests use `base_dir` / `output_dir` injection and `tempfile` dirs — never the
  real `~/.securelink/`. Keep this pattern; do not hard-code home paths in code
  that tests must exercise.
- Public crypto/capsule functions validate input lengths and raise rather than
  returning sentinels.

## Known gaps (do not assume these work)

- **WAN reliability is Go-Back-N** — windowed and loss-tested, but a lost frame
  retransmits the whole window. Selective-repeat is the efficiency follow-up.
- **NAT hole punching is not coordinated.** STUN discovers each peer's public
  endpoint, but exchanging those endpoints and the simultaneous-open punch is
  still manual/out-of-band; no TURN-style relay is bundled.
- **VLAN** is policy enforcement + metadata only — no 802.1Q tagged-frame
  generation.
- `core/__init__.py`, `security/__init__.py`, `ui/__init__.py` are package
  markers; there is no `__init__.py` re-export surface to keep in sync.
