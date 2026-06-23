from __future__ import annotations

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt5.QtWidgets import QApplication

from ui.dashboard import DashboardWindow


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
