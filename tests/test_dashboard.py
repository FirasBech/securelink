from __future__ import annotations

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import time

from PyQt5.QtWidgets import QApplication, QMessageBox

import ui.dashboard as dashboard
from core.settings import Settings
from ui.dashboard import DashboardWindow


class _FakeStats:
    bytes_transferred = 5
    chunks = 1


def _wait_for(predicate, timeout: float = 2.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.02)
    return False


def test_dashboard_window_initializes_offscreen() -> None:
    app = QApplication.instance() or QApplication([])
    window = DashboardWindow(auto_refresh=False)

    assert window.windowTitle() == "SecureLink Dashboard"
    # The receive panel is present and idle on launch.
    assert window.receive_button.text() == "Start Listening"
    assert window.recv_port_spin.value() == 55000
    assert "WAN" in window.recv_wan_checkbox.text()

    # Log search and alerts-only filtering.
    window._render_logs(
        [
            {"event": "transfer", "alert": False, "message": "ok"},
            {"event": "arp_spoof", "alert": True, "message": "arp changed"},
        ],
        [{"event": "arp_spoof", "alert": True, "message": "arp changed"}],
    )
    assert window.log_table.rowCount() == 2
    window.log_search_edit.setText("arp")
    assert window.log_table.rowCount() == 1
    window.log_search_edit.setText("")
    window.log_alerts_only_checkbox.setChecked(True)
    assert window.log_table.rowCount() == 1

    window.close()
    window.deleteLater()

    if app is not None:
        app.quit()


def test_dashboard_friendly_ux() -> None:
    app = QApplication.instance() or QApplication([])
    window = DashboardWindow(auto_refresh=False)

    # Primary actions are styled as primary; key inputs carry tooltips.
    assert window.send_button.objectName() == "PrimaryButton"
    assert window.receive_button.objectName() == "PrimaryButton"
    assert window.peer_host_edit.toolTip()
    assert window.mode_combo.toolTip()
    assert window.recv_port_spin.toolTip()

    # The device table shows an empty-state hint until peers are found,
    # then hides it. (isHidden reflects the explicit setVisible state even
    # though the offscreen window is never shown.)
    window._render_network_table([])
    assert not window.network_hint_label.isHidden()
    window._render_network_table([{"name": "host", "address": "192.168.1.9", "port": 55000}])
    assert window.network_hint_label.isHidden()

    window.close()
    window.deleteLater()
    if app is not None:
        app.quit()


def test_dashboard_is_tabbed() -> None:
    from PyQt5.QtWidgets import QTabWidget

    app = QApplication.instance() or QApplication([])
    window = DashboardWindow(auto_refresh=False)
    tabs = window.findChild(QTabWidget)
    assert tabs is not None
    labels = [tabs.tabText(i).strip() for i in range(tabs.count())]
    assert labels == ["Send", "Receive", "Network", "Activity", "Settings"]
    window.close()
    window.deleteLater()
    if app is not None:
        app.quit()


def test_dashboard_settings_panel_saves(tmp_path, monkeypatch) -> None:
    app = QApplication.instance() or QApplication([])
    window = DashboardWindow(auto_refresh=False)
    window._settings_base_dir = tmp_path

    # A valid BYO coordination server persists.
    window.set_rendezvous_edit.setText("my.server:6000")
    window.set_relay_edit.setText("")
    window._save_settings()
    assert Settings.load(tmp_path).rendezvous == "my.server:6000"
    assert window.settings_status_label.text() == "Saved"

    # An invalid address is rejected and nothing is overwritten.
    monkeypatch.setattr(QMessageBox, "warning", staticmethod(lambda *a, **k: None))
    window.set_rendezvous_edit.setText("nonsense-no-port")
    window._save_settings()
    assert Settings.load(tmp_path).rendezvous == "my.server:6000"

    window.close()
    window.deleteLater()
    if app is not None:
        app.quit()


def test_internet_send_routes_through_coordination_when_token_set(tmp_path, monkeypatch) -> None:
    app = QApplication.instance() or QApplication([])
    window = DashboardWindow(auto_refresh=False)
    window._settings_base_dir = tmp_path
    monkeypatch.setattr(QMessageBox, "warning", staticmethod(lambda *a, **k: None))

    calls: list[tuple] = []

    def fake_wan_send(file_path, *, rendezvous_addr, token, relay_addr=None, **kwargs):
        calls.append((token, rendezvous_addr, relay_addr))
        return _FakeStats()

    monkeypatch.setattr(dashboard, "wan_send_file", fake_wan_send)

    source = tmp_path / "f.bin"
    source.write_bytes(b"hello")
    window.file_edit.setText(str(source))
    window.send_token_edit.setText("alice-bob")

    # No rendezvous configured yet -> rejected, no coordinated call.
    window.send_selected_file()
    assert calls == []

    # Configure a rendezvous (and relay) -> the coordinated path is used.
    Settings(rendezvous="rdv.example:6000", relay="relay.example:6001").save(tmp_path)
    window.send_selected_file()
    assert _wait_for(lambda: bool(calls)), "wan_send_file was not called"
    assert calls[0] == ("alice-bob", ("rdv.example", 6000), ("relay.example", 6001))

    window.close()
    window.deleteLater()
    if app is not None:
        app.quit()


def test_internet_receive_routes_through_coordination_when_token_set(tmp_path, monkeypatch) -> None:
    app = QApplication.instance() or QApplication([])
    window = DashboardWindow(auto_refresh=False)
    window._settings_base_dir = tmp_path
    Settings(rendezvous="rdv.example:6000").save(tmp_path)

    calls: list[tuple] = []

    def fake_wan_recv(*, rendezvous_addr, token, relay_addr=None, **kwargs):
        calls.append((token, rendezvous_addr, relay_addr))
        return (tmp_path / "got.bin", _FakeStats())

    monkeypatch.setattr(dashboard, "wan_receive_file", fake_wan_recv)

    window.recv_token_edit.setText("alice-bob")
    window.recv_output_edit.setText(str(tmp_path))
    window.toggle_receiving()
    assert _wait_for(lambda: bool(calls)), "wan_receive_file was not called"
    assert calls[0] == ("alice-bob", ("rdv.example", 6000), None)

    window.close()
    window.deleteLater()
    if app is not None:
        app.quit()


def test_received_files_panel_lists_arrivals(tmp_path) -> None:
    from PyQt5.QtCore import Qt

    app = QApplication.instance() or QApplication([])
    window = DashboardWindow(auto_refresh=False)

    # Starts with just the placeholder hint, no real entries.
    assert window.received_list.count() == 1
    assert window.received_list.item(0).data(Qt.UserRole) is None

    got = tmp_path / "report.pdf"
    got.write_bytes(b"x" * 1234)
    window._on_receive_finished(str(got), 1234, 3)

    # Placeholder replaced by one real, openable entry (newest first).
    assert window.received_list.count() == 1
    item = window.received_list.item(0)
    assert item.data(Qt.UserRole) == str(got)
    assert "report.pdf" in item.text()
    assert item.toolTip() == str(got)

    # A second arrival stacks on top.
    other = tmp_path / "photo.png"
    other.write_bytes(b"y" * 10)
    window._on_receive_finished(str(other), 10, 1)
    assert window.received_list.count() == 2
    assert window.received_list.item(0).data(Qt.UserRole) == str(other)

    window.close()
    window.deleteLater()
    if app is not None:
        app.quit()


def test_dashboard_tailscale_hint_and_pulse() -> None:
    app = QApplication.instance() or QApplication([])
    window = DashboardWindow(auto_refresh=False)

    # The Tailscale login nudge shows only when there is something to say.
    window._render_tailscale_state({"summary": ""})
    assert window.tailscale_hint_label.isHidden()
    window._render_tailscale_state({"summary": "run 'tailscale up' to use VPN peers."})
    assert not window.tailscale_hint_label.isHidden()
    assert "tailscale up" in window.tailscale_hint_label.text()

    # The activity pulse starts/stops cleanly and is idempotent.
    window._start_pulse(window.transfer_detail_label)
    window._start_pulse(window.transfer_detail_label)
    window._stop_pulse(window.transfer_detail_label)
    window._stop_pulse(window.transfer_detail_label)

    window.close()
    window.deleteLater()
    if app is not None:
        app.quit()


def test_dashboard_vpn_mode_and_local_addresses() -> None:
    app = QApplication.instance() or QApplication([])
    window = DashboardWindow(auto_refresh=False)

    # "VPN" is selectable and forces a direct (non-WAN) transfer.
    assert "VPN" in [window.mode_combo.itemText(i) for i in range(window.mode_combo.count())]
    window.mode_combo.setCurrentText("VPN")
    assert window._resolve_transport_mode("100.64.0.5", None) == "vpn"

    # Auto mode delegates to the shared selector: a Tailscale/CGNAT peer -> vpn,
    # a public peer -> wan, a private peer -> lan.
    window.mode_combo.setCurrentText("Auto")
    assert window._resolve_transport_mode("100.101.0.9", None) == "vpn"
    assert window._resolve_transport_mode("8.8.8.8", None) == "wan"
    assert window._resolve_transport_mode("192.168.1.20", None) == "lan"

    # The Receive panel surfaces shareable addresses, VPN labelled.
    window._render_local_addresses(
        [{"address": "100.64.0.7", "kind": "vpn"}, {"address": "192.168.1.20", "kind": "lan"}]
    )
    text = window.local_addr_label.text()
    assert "100.64.0.7 (VPN)" in text
    assert "192.168.1.20 (LAN)" in text

    window._render_local_addresses([])
    assert "No reachable address" in window.local_addr_label.text()

    window.close()
    window.deleteLater()

    if app is not None:
        app.quit()
