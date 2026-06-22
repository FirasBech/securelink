from __future__ import annotations

import socket
import threading
import time

from core.transport import TransportConfig, receive_file, send_file


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def test_send_file_reports_monotonic_progress(tmp_path) -> None:
    payload = b"x" * 9000  # several LAN chunks
    source = tmp_path / "payload.bin"
    source.write_bytes(payload)

    port = _free_port()
    errors: list[BaseException] = []

    def receiver() -> None:
        try:
            receive_file(
                config=TransportConfig(
                    port=port,
                    bind_host="127.0.0.1",
                    output_dir=tmp_path / "out",
                    allow_unknown=True,
                ),
                base_dir=tmp_path / "recv",
            )
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    thread = threading.Thread(target=receiver, daemon=True)
    thread.start()
    time.sleep(0.25)

    samples: list[tuple[int, int]] = []
    send_file(
        source,
        "127.0.0.1",
        config=TransportConfig(port=port, bind_host="127.0.0.1", allow_unknown=True),
        base_dir=tmp_path / "send",
        progress=lambda sent, total: samples.append((sent, total)),
    )
    thread.join(timeout=5)

    assert not errors, f"receiver failed: {errors!r}"
    assert samples, "progress callback was never called"
    assert {total for _, total in samples} == {len(payload)}  # total constant
    sent_values = [sent for sent, _ in samples]
    assert sent_values == sorted(sent_values)  # monotonically increasing
    assert sent_values[-1] == len(payload)  # ends at 100%
