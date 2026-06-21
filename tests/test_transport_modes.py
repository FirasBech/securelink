from __future__ import annotations

import shutil
import socket
import tempfile
import threading
import time
from pathlib import Path

import pytest

import core.transport as transport
from core.transport import TransportConfig, receive_file, send_file


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@pytest.mark.parametrize("mode", ["lan", "vlan"])
def test_transport_round_trip_loopback(mode: str, monkeypatch: pytest.MonkeyPatch) -> None:
    root = Path(tempfile.mkdtemp(prefix=f"securelink-{mode}-"))
    try:
        sender_base = root / "sender"
        receiver_base = root / "receiver"
        sender_out = root / "sender-out"
        receiver_out = root / "receiver-out"
        for path in (sender_base, receiver_base, sender_out, receiver_out):
            path.mkdir(parents=True, exist_ok=True)

        payload = (f"{mode}-payload-".encode("utf-8") * 2500)[:18000]
        source = root / f"{mode}.bin"
        source.write_bytes(payload)
        port = _free_port()
        results: dict[str, object] = {}
        errors: list[BaseException] = []
        vlan_id = 123 if mode == "vlan" else None

        def receiver() -> None:
            try:
                cfg = TransportConfig(
                    mode=mode,
                    port=port,
                    bind_host="127.0.0.1",
                    output_dir=receiver_out,
                    allow_unknown=True,
                    vlan_id=vlan_id,
                )
                results["recv"] = receive_file(config=cfg, base_dir=receiver_base)
            except BaseException as exc:
                errors.append(exc)

        thread = threading.Thread(target=receiver, daemon=True)
        thread.start()
        time.sleep(0.25)

        cfg = TransportConfig(
            mode=mode,
            port=port,
            bind_host="127.0.0.1",
            output_dir=sender_out,
            allow_unknown=True,
            vlan_id=vlan_id,
        )
        results["send"] = send_file(source, "127.0.0.1", config=cfg, base_dir=sender_base)

        thread.join(timeout=10)
        assert not thread.is_alive(), f"{mode} receiver did not finish"
        assert not errors, f"{mode} receiver failed: {errors!r}"

        recv_path, recv_stats = results["recv"]
        send_stats = results["send"]
        assert Path(recv_path).read_bytes() == payload
        assert send_stats.bytes_transferred == len(payload)
        assert recv_stats.bytes_transferred == len(payload)
    finally:
        shutil.rmtree(root, ignore_errors=True)