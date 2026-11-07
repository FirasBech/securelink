from __future__ import annotations

import base64
import json
import os
import socket
import struct
import threading
from collections.abc import Sequence
from dataclasses import dataclass, field, replace
from hashlib import sha256
from pathlib import Path, PurePosixPath
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
    files: int = 0


@dataclass(frozen=True)
class TransferItem:
    """One file or directory in a transfer.

    ``relative_path`` is always POSIX-style (``folder/sub/file.txt``) and is
    resolved beneath the receiver's output directory, so the sender's absolute
    paths never leak and the receiver can create the same folder structure.
    """

    source: Path
    relative_path: str
    size: int = 0
    is_dir: bool = False



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


MANIFEST_CHUNK_SIZE = 48 * 1024
MAX_MANIFEST_CHUNKS = 100_000


def _unique_relative_path(relative_path: str, used: set[str]) -> str:
    """Return ``relative_path`` or a ``name (2).ext`` variant not in ``used``."""

    if os.path.normcase(relative_path) not in used:
        return relative_path
    path = PurePosixPath(relative_path)
    for counter in range(2, 10_000):
        candidate_name = f"{path.stem} ({counter}){path.suffix}"
        candidate = (
            str(path.parent / candidate_name)
            if str(path.parent) != "."
            else candidate_name
        )
        if os.path.normcase(candidate) not in used:
            return candidate
    raise TransportError(f"too many name collisions for {relative_path!r}")


def _join_relative(root: str, relative_dir: Path, name: str) -> str:
    if relative_dir == Path("."):
        return f"{root}/{name}"
    return f"{root}/{relative_dir.as_posix()}/{name}"


def collect_transfer_items(
    paths: str | Path | Sequence[str | Path],
) -> list[TransferItem]:
    """Expand files and folders into an ordered list of transfer entries.

    A folder is sent under its own name (``photos/...``) with its structure
    preserved, including empty directories. Symlinks are skipped so a selection
    can never pull in files outside the chosen tree, and duplicate names get a
    ``" (2)"`` suffix instead of overwriting each other.
    """

    if isinstance(paths, (str, Path)):
        sources = [Path(paths)]
    else:
        sources = [Path(item) for item in paths]

    items: list[TransferItem] = []
    used: set[str] = set()

    def add(entry: TransferItem) -> None:
        relative = entry.relative_path
        if os.path.normcase(relative) in used:
            relative = _unique_relative_path(relative, used)
            entry = replace(entry, relative_path=relative)
        used.add(os.path.normcase(relative))
        items.append(entry)

    for source in sources:
        source = source.expanduser()
        if not source.exists():
            raise FileNotFoundError(source)
        if source.is_dir():
            root = _unique_relative_path(source.name or "folder", used)
            add(TransferItem(source, root, is_dir=True))
            for directory, dirnames, filenames in os.walk(source, followlinks=False):
                current = Path(directory)
                dirnames[:] = sorted(
                    name for name in dirnames if not (current / name).is_symlink()
                )
                for name in dirnames:
                    child = current / name
                    add(
                        TransferItem(
                            child,
                            _join_relative(root, current.relative_to(source), name),
                            is_dir=True,
                        )
                    )
                for name in sorted(filenames):
                    child = current / name
                    if child.is_symlink() or not child.is_file():
                        continue
                    add(
                        TransferItem(
                            child,
                            _join_relative(root, current.relative_to(source), name),
                            child.stat().st_size,
                        )
                    )
        elif source.is_file():
            add(
                TransferItem(
                    source,
                    _unique_relative_path(source.name, used),
                    source.stat().st_size,
                )
            )
        else:
            raise ValueError(f"unsupported path type: {source}")

    if not items:
        raise TransportError("nothing to send")
    return items


def _safe_output_path(output_dir: Path, relative_path: str) -> Path:
    """Resolve a manifest path beneath ``output_dir``, rejecting escapes.

    A manifest is authenticated but still untrusted input: ``../``, absolute
    paths, Windows drive letters and NUL bytes must never choose where a file is
    written on the receiving machine.
    """

    if not relative_path or "\x00" in relative_path:
        raise TransportError("invalid relative path in manifest")
    pure = PurePosixPath(relative_path.replace("\\", "/"))
    parts = pure.parts
    if pure.is_absolute() or not parts or any(part in {"", ".."} for part in parts):
        raise TransportError(f"unsafe path in manifest: {relative_path!r}")
    if ":" in parts[0]:
        raise TransportError(f"unsafe path in manifest: {relative_path!r}")
    return output_dir.joinpath(*parts)


def _build_manifest(items: Sequence[TransferItem], config: TransportConfig) -> dict[str, Any]:
    base: dict[str, Any] = {
        "mode": config.mode,
        "mtu": config.mtu,
        "vlan_id": config.vlan_id,
    }
    # One regular file uses the original single-file manifest, so an older
    # SecureLink peer can still receive it. Everything else uses protocol v2.
    if len(items) == 1 and not items[0].is_dir:
        return {**base, "filename": items[0].relative_path, "file_size": items[0].size}
    return {
        **base,
        "manifest_version": 2,
        "items": [
            {
                "path": item.relative_path,
                "size": item.size,
                "type": "dir" if item.is_dir else "file",
            }
            for item in items
        ],
    }


def _send_manifest(channel: FrameChannel, manifest: dict[str, Any]) -> None:
    """Send a manifest, splitting it into frames when it is too large.

    A folder with thousands of files can produce a manifest bigger than one
    reliable-UDP datagram; the receiver reassembles those frames.
    """

    encoded = json.dumps(manifest, separators=(",", ":")).encode("utf-8")
    if len(encoded) <= MANIFEST_CHUNK_SIZE:
        channel.send_frame(encoded)
        return
    chunk_count = (len(encoded) + MANIFEST_CHUNK_SIZE - 1) // MANIFEST_CHUNK_SIZE
    header = {
        "manifest_chunks": chunk_count,
        "manifest_bytes": len(encoded),
        "manifest_version": manifest.get("manifest_version", 2),
    }
    channel.send_frame(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    for offset in range(0, len(encoded), MANIFEST_CHUNK_SIZE):
        channel.send_frame(encoded[offset : offset + MANIFEST_CHUNK_SIZE])


def _recv_manifest(channel: FrameChannel) -> dict[str, Any]:
    first = _recv_json(channel)
    chunk_count = first.get("manifest_chunks")
    if chunk_count is None:
        return first
    try:
        count = int(chunk_count)
    except (TypeError, ValueError) as exc:
        raise TransportError("invalid chunked manifest header") from exc
    if count < 1 or count > MAX_MANIFEST_CHUNKS:
        raise TransportError("invalid chunked manifest size")
    raw = bytearray()
    for _ in range(count):
        raw.extend(channel.recv_frame())
    try:
        decoded = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise TransportError("invalid chunked manifest payload") from exc
    if not isinstance(decoded, dict):
        raise TransportError("invalid chunked manifest payload")
    return decoded


def _manifest_entries(manifest: dict[str, Any]) -> list[tuple[str, int, bool]]:
    """Normalise a v1 (single file) or v2 (items) manifest."""

    raw_items = manifest.get("items")
    if isinstance(raw_items, list):
        entries: list[tuple[str, int, bool]] = []
        seen: set[str] = set()
        for raw in raw_items:
            if not isinstance(raw, dict):
                raise TransportError("invalid item in manifest")
            relative = str(raw.get("path") or "")
            try:
                size = int(raw.get("size") or 0)
            except (TypeError, ValueError) as exc:
                raise TransportError("invalid item size in manifest") from exc
            if size < 0:
                raise TransportError("negative item size in manifest")
            is_dir = str(raw.get("type") or "file").lower() == "dir"
            key = os.path.normcase(relative.replace("\\", "/"))
            if key in seen:
                raise TransportError(f"duplicate path in manifest: {relative!r}")
            seen.add(key)
            entries.append((relative, size, is_dir))
        if not entries:
            raise TransportError("empty manifest")
        return entries

    filename = str(manifest.get("filename") or "securelink-transfer.bin")
    try:
        file_size = int(manifest.get("file_size") or 0)
    except (TypeError, ValueError) as exc:
        raise TransportError("invalid file size in manifest") from exc
    if file_size < 0:
        raise TransportError("negative file size in manifest")
    return [(filename, file_size, False)]



def stream_send_items(
    channel: FrameChannel,
    items: Sequence[TransferItem],
    transfer_config: TransportConfig,
    *,
    trust_prompt: Callable[[str], bool] | None = None,
    base_dir: Path | None = None,
    chunk_size: int | None = None,
    progress: Callable[[int, int], None] | None = None,
    item_started: Callable[[str, int, int], None] | None = None,
) -> TransferStats:
    """Run the client handshake and stream files/folders as capsules.

    Transport-agnostic: works over any :class:`FrameChannel` (TCP or reliable
    UDP). All files share one session and one continuous capsule sequence;
    directory entries are carried in the manifest so empty folders survive.
    ``progress`` is called after each chunk with ``(bytes_sent, total_bytes)``;
    ``item_started`` is called before each file with
    ``(relative_path, index, file_count)``.
    """

    if not items:
        raise TransportError("nothing to send")
    file_items = [item for item in items if not item.is_dir]
    total = sum(item.size for item in file_items)
    stats = TransferStats()

    handshake = _perform_client_handshake(
        channel,
        allow_unknown=transfer_config.allow_unknown,
        trust_prompt=trust_prompt,
        base_dir=base_dir,
    )
    _send_manifest(channel, _build_manifest(items, transfer_config))
    read_size = chunk_size if chunk_size is not None else lan_chunk_size(transfer_config.mtu)

    sequence = 0
    for index, item in enumerate(file_items, start=1):
        if item_started is not None:
            item_started(item.relative_path, index, len(file_items))
        if not item.source.is_file():
            raise FileNotFoundError(item.source)
        remaining = item.size
        with item.source.open("rb") as handle:
            while remaining > 0:
                plaintext = handle.read(min(read_size, remaining))
                if not plaintext:
                    raise TransportError(
                        f"{item.relative_path} ended before its declared size"
                    )
                capsule = build_capsule(
                    plaintext,
                    chunk_id=sequence,
                    session_keys=handshake.session_keys,
                )
                channel.send_frame(capsule)
                remaining -= len(plaintext)
                stats.bytes_transferred += len(plaintext)
                stats.chunks += 1
                sequence += 1
                if progress is not None:
                    progress(stats.bytes_transferred, total)
        stats.files += 1

    # Confirm every frame landed before the channel closes (matters for UDP,
    # where the last unacked frames would otherwise be lost on close).
    channel.flush()
    return stats


def stream_send(
    channel: FrameChannel,
    transfer_path: Path,
    transfer_config: TransportConfig,
    **kwargs: Any,
) -> TransferStats:
    """Send a single file as capsules over ``channel`` (compatibility wrapper)."""

    return stream_send_items(
        channel,
        collect_transfer_items(transfer_path),
        transfer_config,
        **kwargs,
    )


def stream_receive_items(
    channel: FrameChannel,
    transfer_config: TransportConfig,
    *,
    trust_prompt: Callable[[str], bool] | None = None,
    base_dir: Path | None = None,
) -> tuple[list[Path], TransferStats]:
    """Run the server handshake and reassemble a (possibly multi-file) stream."""

    stats = TransferStats()
    output_dir = transfer_config.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)

    handshake = _perform_server_handshake(
        channel,
        allow_unknown=transfer_config.allow_unknown,
        trust_prompt=trust_prompt,
        base_dir=base_dir,
    )
    entries = _manifest_entries(_recv_manifest(channel))
    tracker = SequenceTracker(strict=True)
    written: list[Path] = []

    for relative_path, file_size, is_dir in entries:
        output_path = _safe_output_path(output_dir, relative_path)
        if is_dir:
            output_path.mkdir(parents=True, exist_ok=True)
            continue
        output_path.parent.mkdir(parents=True, exist_ok=True)
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
                if received + len(plaintext) > file_size:
                    raise TransportError(
                        f"{relative_path} carried more data than its declared size"
                    )
                handle.write(plaintext)
                received += len(plaintext)
                stats.bytes_transferred += len(plaintext)
                stats.chunks += 1
        written.append(output_path)
        stats.files += 1
    return written, stats


def stream_receive(
    channel: FrameChannel,
    transfer_config: TransportConfig,
    **kwargs: Any,
) -> tuple[Path, TransferStats]:
    """Receive a single file (compatibility wrapper around :func:`stream_receive_items`)."""

    paths, stats = stream_receive_items(channel, transfer_config, **kwargs)
    return (paths[0] if paths else transfer_config.output_dir), stats



def send_paths(
    paths: str | Path | Sequence[str | Path],
    peer_host: str,
    *,
    config: TransportConfig | None = None,
    trust_prompt: Callable[[str], bool] | None = None,
    base_dir: Path | None = None,
    progress: Callable[[int, int], None] | None = None,
    item_started: Callable[[str, int, int], None] | None = None,
) -> TransferStats:
    """Send one or more files/folders to ``peer_host`` over a single TCP session."""

    items = collect_transfer_items(paths)
    transfer_config = config or TransportConfig()

    with socket.create_connection((peer_host, transfer_config.port)) as sock:
        return stream_send_items(
            _StreamChannel(sock),
            items,
            transfer_config,
            trust_prompt=trust_prompt,
            base_dir=base_dir,
            progress=progress,
            item_started=item_started,
        )


def send_file(
    file_path: str | Path,
    peer_host: str,
    *,
    config: TransportConfig | None = None,
    trust_prompt: Callable[[str], bool] | None = None,
    base_dir: Path | None = None,
    progress: Callable[[int, int], None] | None = None,
) -> TransferStats:
    """Send a single file to ``peer_host`` (compatibility wrapper)."""

    return send_paths(
        file_path,
        peer_host,
        config=config,
        trust_prompt=trust_prompt,
        base_dir=base_dir,
        progress=progress,
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


def receive_paths(
    *,
    config: TransportConfig | None = None,
    trust_prompt: Callable[[str], bool] | None = None,
    base_dir: Path | None = None,
    cancel_event: threading.Event | None = None,
) -> tuple[list[Path], TransferStats]:
    """Accept one connection and receive every file/folder it carries."""

    transfer_config = config or TransportConfig()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((transfer_config.bind_host, transfer_config.port))
        server_socket.listen(1)
        connection, address = _accept(server_socket, cancel_event)
        with connection:
            _validate_allowlist(address[0], transfer_config.allowlist)
            return stream_receive_items(
                _StreamChannel(connection),
                transfer_config,
                trust_prompt=trust_prompt,
                base_dir=base_dir,
            )


def receive_file(
    *,
    config: TransportConfig | None = None,
    trust_prompt: Callable[[str], bool] | None = None,
    base_dir: Path | None = None,
    cancel_event: threading.Event | None = None,
) -> tuple[Path, TransferStats]:
    transfer_config = config or TransportConfig()
    paths, stats = receive_paths(
        config=transfer_config,
        trust_prompt=trust_prompt,
        base_dir=base_dir,
        cancel_event=cancel_event,
    )
    return (paths[0] if paths else transfer_config.output_dir), stats
