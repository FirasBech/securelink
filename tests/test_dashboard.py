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

    window.close()
    window.deleteLater()

    if app is not None:
        app.quit()
