from __future__ import annotations

import base64
import json
import os
import socket
import struct
import threading
from dataclasses import dataclass, field
from hashlib import sha256
from pathlib import Path
from typing import Any, Callable, Protocol

from .auth import confirm_or_record_remote_device, load_or_create_identity, sign_message, verify_signature
from .capsule import SequenceTracker, build_capsule, parse_capsule
from .crypto import SessionKeys, KeyExchange, lan_chunk_size

FRAME_LENGTH_SIZE = 4
DEFAULT_PORT = 55000
DEFAULT_MODE = "lan"


@dataclass
class TransferStats:
    bytes_transferred: int = 0
    chunks: int = 0
    alerts: int = 0


@dataclass(frozen=True)
class TransportConfig:
    mode: str = DEFAULT_MODE
    port: int = DEFAULT_PORT
    mtu: int = 1500
    allow_unknown: bool = False
    vlan_id: int | None = None
    allowlist: tuple[str, ...] = ()
    bind_host: str = "0.0.0.0"
    output_dir: Path = field(default_factory=lambda: Path.cwd())


@dataclass(frozen=True)
class HandshakeResult:
    session_keys: SessionKeys
    peer_fingerprint: str
    peer_public_key: bytes
    peer_address: str | None = None


class TransportError(RuntimeError):
    pass


def _send_frame(sock: socket.socket, payload: bytes) -> None:
    sock.sendall(struct.pack("!I", len(payload)) + payload)


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    buffer = bytearray()
    while len(buffer) < size:
        chunk = sock.recv(size - len(buffer))
        if not chunk:
            raise EOFError("unexpected end of stream")
        buffer.extend(chunk)
    return bytes(buffer)


def _recv_frame(sock: socket.socket) -> bytes:
    frame_size = struct.unpack("!I", _recv_exact(sock, FRAME_LENGTH_SIZE))[0]
    return _recv_exact(sock, frame_size)


class FrameChannel(Protocol):
    """A bidirectional channel that exchanges length-delimited messages.

    Both the TCP transport (:class:`_StreamChannel`) and the reliable UDP
    transport (``core.udp_transport.ReliableUdpChannel``) implement this so the
    handshake and capsule-streaming code can be shared across modes.
    """

    def send_frame(self, payload: bytes) -> None: ...

    def recv_frame(self) -> bytes: ...

    def flush(self) -> None:
        """Block until all sent frames are confirmed delivered (no-op if the
        underlying transport is already reliable)."""
        ...


class _StreamChannel:
    """FrameChannel backed by a connected stream socket (TCP)."""

    __slots__ = ("_sock",)

    def __init__(self, sock: socket.socket) -> None:
        self._sock = sock

    def send_frame(self, payload: bytes) -> None:
        _send_frame(self._sock, payload)

    def recv_frame(self) -> bytes:
        return _recv_frame(self._sock)

    def flush(self) -> None:
        # TCP guarantees in-order reliable delivery; nothing to confirm.
        return None


def _send_json(channel: FrameChannel, payload: dict[str, Any]) -> None:
    encoded = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    channel.send_frame(encoded)


def _recv_json(channel: FrameChannel) -> dict[str, Any]:
    payload = channel.recv_frame()
    decoded = json.loads(payload.decode("utf-8"))
    if not isinstance(decoded, dict):
        raise TransportError("invalid JSON payload")
    return decoded


def _make_handshake_payload(identity_public_key: bytes, ephemeral_public_key: bytes, signature: bytes, nonce: bytes) -> dict[str, str]:
    return {
        "identity_public_key": base64.b64encode(identity_public_key).decode("ascii"),
        "ephemeral_public_key": base64.b64encode(ephemeral_public_key).decode("ascii"),
        "signature": base64.b64encode(signature).decode("ascii"),
        "nonce": base64.b64encode(nonce).decode("ascii"),
    }


def _parse_handshake_payload(payload: dict[str, Any]) -> tuple[bytes, bytes, bytes, bytes]:
    try:
        identity_public_key = base64.b64decode(payload["identity_public_key"])
        ephemeral_public_key = base64.b64decode(payload["ephemeral_public_key"])
        signature = base64.b64decode(payload["signature"])
        nonce = base64.b64decode(payload["nonce"])
    except Exception as exc:
        raise TransportError("invalid handshake payload") from exc
    return identity_public_key, ephemeral_public_key, signature, nonce


def _trust_prompt_factory(confirm: Callable[[str], bool] | None) -> Callable[[str], bool]:
    if confirm is not None:
        return confirm

    def _prompt(fingerprint: str) -> bool:
        answer = input(f"Trust remote device {fingerprint}? [y/N] ").strip().lower()
        return answer in {"y", "yes"}

    return _prompt


def _derive_session_result(
    *,
    kex: KeyExchange,
    peer_public_key: bytes,
    local_nonce: bytes,
    peer_nonce: bytes,
) -> SessionKeys:
    salt_seed = b"".join(sorted((local_nonce, peer_nonce))) + b"securelink"
    salt = sha256(salt_seed).digest()[:16]
    return kex.derive(peer_public_key, salt=salt)


def _validate_allowlist(peer_address: str, allowlist: tuple[str, ...]) -> None:
    if not allowlist:
        return
    peer_ip = peer_address.strip()
    for network in allowlist:
        try:
            import ipaddress

            if "/" in network:
                if ipaddress.ip_address(peer_ip) in ipaddress.ip_network(network, strict=False):
                    return
            elif peer_ip == network:
                return
        except Exception:
            continue
    raise PermissionError(f"peer {peer_ip} is not allowed by the configured allowlist")


def _resolve_host_address(host: str) -> str:
    try:
        return socket.gethostbyname(host)
    except socket.gaierror as exc:
        raise TransportError(f"unable to resolve host {host!r}") from exc


def _perform_client_handshake(
    channel: FrameChannel,
    *,
    allow_unknown: bool,
    trust_prompt: Callable[[str], bool] | None,
    base_dir: Path | None = None,
) -> HandshakeResult:
    identity = load_or_create_identity(base_dir)
    kex = KeyExchange()
    local_nonce = os.urandom(16)
    local_public_key_bytes = kex.public_bytes()
    signature = sign_message(identity.private_key, local_public_key_bytes + local_nonce)
    _send_json(
        channel,
        _make_handshake_payload(identity.public_key, local_public_key_bytes, signature, local_nonce),
    )
    peer_identity_public_key, peer_ephemeral_public_key, peer_signature, peer_nonce = _parse_handshake_payload(_recv_json(channel))
    if not verify_signature(peer_identity_public_key, peer_signature, peer_ephemeral_public_key + peer_nonce):
        raise TransportError("remote device failed signature verification")
    confirmer = _trust_prompt_factory(trust_prompt)
    accepted, fingerprint = confirm_or_record_remote_device(
        peer_identity_public_key,
        allow_unknown=allow_unknown,
        base_dir=base_dir,
        confirmer=confirmer,
    )
    if not accepted:
        raise PermissionError(f"remote device {fingerprint} was rejected")
    session_keys = _derive_session_result(
        kex=kex,
        peer_public_key=peer_ephemeral_public_key,
        local_nonce=local_nonce,
        peer_nonce=peer_nonce,
    )
    return HandshakeResult(session_keys=session_keys, peer_fingerprint=fingerprint, peer_public_key=peer_identity_public_key)


def _perform_server_handshake(
    channel: FrameChannel,
    *,
    allow_unknown: bool,
    trust_prompt: Callable[[str], bool] | None,
    base_dir: Path | None = None,
) -> HandshakeResult:
    identity = load_or_create_identity(base_dir)
    client_identity_public_key, client_ephemeral_public_key, client_signature, client_nonce = _parse_handshake_payload(_recv_json(channel))
    if not verify_signature(client_identity_public_key, client_signature, client_ephemeral_public_key + client_nonce):
        raise TransportError("client device failed signature verification")
    confirmer = _trust_prompt_factory(trust_prompt)
    accepted, fingerprint = confirm_or_record_remote_device(
        client_identity_public_key,
        allow_unknown=allow_unknown,
        base_dir=base_dir,
        confirmer=confirmer,
    )
    if not accepted:
        raise PermissionError(f"remote device {fingerprint} was rejected")

    local_nonce = os.urandom(16)
    kex = KeyExchange()
    local_public_key_bytes = kex.public_bytes()
    signature = sign_message(identity.private_key, local_public_key_bytes + local_nonce)
    _send_json(
        channel,
        _make_handshake_payload(identity.public_key, local_public_key_bytes, signature, local_nonce),
    )
    session_keys = _derive_session_result(
        kex=kex,
        peer_public_key=client_ephemeral_public_key,
        local_nonce=local_nonce,
        peer_nonce=client_nonce,
    )
    return HandshakeResult(session_keys=session_keys, peer_fingerprint=fingerprint, peer_public_key=client_identity_public_key)


def _build_manifest(file_path: Path, config: TransportConfig) -> dict[str, Any]:
    file_size = file_path.stat().st_size
    return {
        "filename": file_path.name,
        "file_size": file_size,
        "mode": config.mode,
        "mtu": config.mtu,
        "vlan_id": config.vlan_id,
    }


def stream_send(
    channel: FrameChannel,
    transfer_path: Path,
    transfer_config: TransportConfig,
    *,
    trust_prompt: Callable[[str], bool] | None = None,
    base_dir: Path | None = None,
    chunk_size: int | None = None,
) -> TransferStats:
    """Run the client handshake and stream a file as capsules over ``channel``.

    Transport-agnostic: works over any :class:`FrameChannel` (TCP or reliable
    UDP). ``chunk_size`` overrides the MTU-derived plaintext read size for
    datagram transports that must avoid IP fragmentation.
    """

    stats = TransferStats()
    handshake = _perform_client_handshake(
        channel,
        allow_unknown=transfer_config.allow_unknown,
        trust_prompt=trust_prompt,
        base_dir=base_dir,
    )
    _send_json(channel, _build_manifest(transfer_path, transfer_config))
    read_size = chunk_size if chunk_size is not None else lan_chunk_size(transfer_config.mtu)

    with transfer_path.open("rb") as handle:
        sequence = 0
        while True:
            plaintext = handle.read(read_size)
            if not plaintext:
                break
            capsule = build_capsule(
                plaintext,
                chunk_id=sequence,
                session_keys=handshake.session_keys,
            )
            channel.send_frame(capsule)
            stats.bytes_transferred += len(plaintext)
            stats.chunks += 1
            sequence += 1

    # Confirm every frame landed before the channel closes (matters for UDP,
    # where the last unacked frames would otherwise be lost on close).
    channel.flush()
    return stats


def stream_receive(
    channel: FrameChannel,
    transfer_config: TransportConfig,
    *,
    trust_prompt: Callable[[str], bool] | None = None,
    base_dir: Path | None = None,
) -> tuple[Path, TransferStats]:
    """Run the server handshake and reassemble a capsule stream from ``channel``."""

    stats = TransferStats()
    output_dir = transfer_config.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)

    handshake = _perform_server_handshake(
        channel,
        allow_unknown=transfer_config.allow_unknown,
        trust_prompt=trust_prompt,
        base_dir=base_dir,
    )
    manifest = _recv_json(channel)
    filename = manifest.get("filename", "securelink-transfer.bin")
    file_size = int(manifest.get("file_size", 0))
    output_path = output_dir / filename
    tracker = SequenceTracker(strict=True)

    received = 0
    with output_path.open("wb") as handle:
        while received < file_size:
            capsule = channel.recv_frame()
            chunk_id, plaintext = parse_capsule(
                capsule,
                handshake.session_keys,
                tracker=tracker,
            )
            if chunk_id != tracker.next_expected - 1:
                raise TransportError("capsule sequence mismatch")
            handle.write(plaintext)
            received += len(plaintext)
            stats.bytes_transferred += len(plaintext)
            stats.chunks += 1
    return output_path, stats


def send_file(
    file_path: str | Path,
    peer_host: str,
    *,
    config: TransportConfig | None = None,
    trust_prompt: Callable[[str], bool] | None = None,
    base_dir: Path | None = None,
) -> TransferStats:
    transfer_path = Path(file_path)
    if not transfer_path.exists():
        raise FileNotFoundError(transfer_path)

    transfer_config = config or TransportConfig()

    with socket.create_connection((peer_host, transfer_config.port)) as sock:
        return stream_send(
            _StreamChannel(sock),
            transfer_path,
            transfer_config,
            trust_prompt=trust_prompt,
            base_dir=base_dir,
        )


def _accept(
    server_socket: socket.socket,
    cancel_event: threading.Event | None,
) -> tuple[socket.socket, Any]:
    """Accept a connection, polling ``cancel_event`` so a caller can stop waiting."""

    if cancel_event is None:
        return server_socket.accept()
    server_socket.settimeout(0.5)
    while True:
        if cancel_event.is_set():
            raise TransportError("listen cancelled")
        try:
            return server_socket.accept()
        except socket.timeout:
            continue


def receive_file(
    *,
    config: TransportConfig | None = None,
    trust_prompt: Callable[[str], bool] | None = None,
    base_dir: Path | None = None,
    cancel_event: threading.Event | None = None,
) -> tuple[Path, TransferStats]:
    transfer_config = config or TransportConfig()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((transfer_config.bind_host, transfer_config.port))
        server_socket.listen(1)
        connection, address = _accept(server_socket, cancel_event)
        with connection:
            _validate_allowlist(address[0], transfer_config.allowlist)
            return stream_receive(
                _StreamChannel(connection),
                transfer_config,
                trust_prompt=trust_prompt,
                base_dir=base_dir,
            )
