from __future__ import annotations

import socket
import threading
import time

from core.transport import TransportConfig, TransportError, receive_file
from core.udp_transport import udp_receive_file


def _free_port(kind: int) -> int:
    with socket.socket(socket.AF_INET, kind) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _run_until_done(target) -> dict[str, object]:
    result: dict[str, object] = {}

    def runner() -> None:
        try:
            target()
        except BaseException as exc:  # noqa: BLE001
            result["error"] = exc

    thread = threading.Thread(target=runner, daemon=True)
    thread.start()
    time.sleep(0.3)  # let the receiver start listening
    return {"thread": thread, "result": result}


def test_receive_file_cancel_stops_listening(tmp_path) -> None:
    cancel = threading.Event()
    config = TransportConfig(
        port=_free_port(socket.SOCK_STREAM),
        bind_host="127.0.0.1",
        output_dir=tmp_path,
        allow_unknown=True,
    )
    state = _run_until_done(
        lambda: receive_file(config=config, base_dir=tmp_path, cancel_event=cancel)
    )

    cancel.set()
    state["thread"].join(timeout=3)
    assert not state["thread"].is_alive(), "TCP receiver ignored cancel"
    assert isinstance(state["result"].get("error"), TransportError)


def test_udp_receive_file_cancel_stops_listening(tmp_path) -> None:
    cancel = threading.Event()
    config = TransportConfig(
        mode="wan",
        port=_free_port(socket.SOCK_DGRAM),
        bind_host="127.0.0.1",
        output_dir=tmp_path,
        allow_unknown=True,
    )
    state = _run_until_done(
        lambda: udp_receive_file(config=config, base_dir=tmp_path, cancel_event=cancel)
    )

    cancel.set()
    state["thread"].join(timeout=3)
    assert not state["thread"].is_alive(), "UDP receiver ignored cancel"
    assert isinstance(state["result"].get("error"), TransportError)
