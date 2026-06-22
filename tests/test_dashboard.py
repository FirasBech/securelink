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
