from __future__ import annotations

import json
import socket
import threading
import time

from ui import cli


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def test_cli_status_uses_isolated_state_dir(tmp_path, capsys) -> None:
    rc = cli.main(["status", "--state-dir", str(tmp_path)])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out == {"bytes_sent": 0, "bytes_received": 0, "chunks": 0, "alerts": 0}


def test_cli_send_recv_round_trip_loopback(tmp_path) -> None:
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    send_state = tmp_path / "send-state"
    recv_state = tmp_path / "recv-state"
    source = tmp_path / "payload.bin"
    source.write_bytes(b"securelink-cli-" * 1000)

    port = _free_port()
    errors: list[BaseException] = []
    rc_recv: dict[str, int] = {}

    def receiver() -> None:
        try:
            rc_recv["code"] = cli.main(
                [
                    "recv",
                    "--port",
                    str(port),
                    "--allow-unknown",
                    "--output-dir",
                    str(out_dir),
                    "--state-dir",
                    str(recv_state),
                ]
            )
        except BaseException as exc:  # noqa: BLE001 - surfaced to the test
            errors.append(exc)

    thread = threading.Thread(target=receiver, daemon=True)
    thread.start()
    time.sleep(0.25)

    rc_send = cli.main(
        [
            "send",
            str(source),
            "127.0.0.1",
            "--port",
            str(port),
            "--allow-unknown",
            "--state-dir",
            str(send_state),
        ]
    )

    thread.join(timeout=10)
    assert not thread.is_alive(), "CLI receiver did not finish"
    assert not errors, f"CLI receiver failed: {errors!r}"
    assert rc_send == 0
    assert rc_recv.get("code") == 0

    assert (out_dir / "payload.bin").read_bytes() == source.read_bytes()
    # State is isolated under --state-dir, never the real home directory.
    assert (send_state / ".securelink" / "session.json").exists()
    assert (recv_state / ".securelink" / "session.json").exists()
    assert (recv_state / ".securelink" / "identity_ed25519.pem").exists()


def test_cli_send_recv_wan_round_trip_loopback(tmp_path) -> None:
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    send_state = tmp_path / "send-state"
    recv_state = tmp_path / "recv-state"
    source = tmp_path / "wan.bin"
    source.write_bytes(b"securelink-wan-cli-" * 800)

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]

    errors: list[BaseException] = []
    rc_recv: dict[str, int] = {}

    def receiver() -> None:
        try:
            rc_recv["code"] = cli.main(
                [
                    "recv",
                    "--wan",
                    "--port",
                    str(port),
                    "--allow-unknown",
                    "--output-dir",
                    str(out_dir),
                    "--state-dir",
                    str(recv_state),
                ]
            )
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    thread = threading.Thread(target=receiver, daemon=True)
    thread.start()
    time.sleep(0.25)

    rc_send = cli.main(
        [
            "send",
            str(source),
            "127.0.0.1",
            "--wan",
            "--port",
            str(port),
            "--allow-unknown",
            "--state-dir",
            str(send_state),
        ]
    )

    thread.join(timeout=15)
    assert not thread.is_alive(), "CLI WAN receiver did not finish"
    assert not errors, f"CLI WAN receiver failed: {errors!r}"
    assert rc_send == 0
    assert rc_recv.get("code") == 0
    assert (out_dir / "wan.bin").read_bytes() == source.read_bytes()
