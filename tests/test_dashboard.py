from __future__ import annotations

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt5.QtWidgets import QApplication

from ui.dashboard import DashboardWindow


def test_dashboard_window_initializes_offscreen() -> None:
    app = QApplication.instance() or QApplication([])
    window = DashboardWindow(auto_refresh=False)

    assert window.windowTitle() == "SecureLink Dashboard"

    window.close()
    window.deleteLater()

    if app is not None:
        app.quit()
