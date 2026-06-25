from __future__ import annotations

import json
import sys
import threading
import time
import traceback
from datetime import date, datetime
from pathlib import Path
from typing import Any

from PyQt5.QtCore import (
    QEasingCurve,
    QFileInfo,
    QPropertyAnimation,
    QSize,
    Qt,
    QTimer,
    QUrl,
    pyqtSignal,
)
from PyQt5.QtGui import QColor, QDesktopServices, QFont, QIcon
from PyQt5.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QDialog,
    QFileDialog,
    QFileIconProvider,
    QFrame,
    QGraphicsOpacityEffect,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QSpinBox,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)

from core.discovery import (
    auto_select_transport_mode,
    discover_peers,
    local_reachable_addresses,
    tailscale_peers,
    tailscale_state,
)
from core.settings import Settings, SettingsError, parse_host_port
from core.transport import TransportConfig, receive_file, send_file
from core.udp_transport import (
    udp_receive_file,
    udp_send_file,
    wan_receive_file,
    wan_send_file,
)

LOG_DIR = Path.home() / ".securelink" / "logs"
ICON_PATH = Path(__file__).resolve().parents[1] / "assets" / "securelink.ico"
APP_USER_MODEL_ID = "FirasBech.SecureLink.Dashboard"


def _claim_taskbar_identity() -> None:
    """Tell Windows this process is its own app, not a generic Python host.

    Without an explicit AppUserModelID the taskbar groups the GUI under
    ``pythonw.exe`` and shows the Python icon. Setting our own id makes Windows
    use the window/application icon instead. No-op off Windows or if the call
    is unavailable.
    """
    if sys.platform != "win32":
        return
    try:
        import ctypes

        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(APP_USER_MODEL_ID)
    except Exception:
        pass


def _read_today_log_entries() -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    log_path = LOG_DIR / f"{date.today().isoformat()}.json"
    if not log_path.exists():
        return [], []

    entries: list[dict[str, Any]] = []
    alerts: list[dict[str, Any]] = []
    for line in log_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(payload, dict):
            continue
        entries.append(payload)
        if payload.get("alert"):
            alerts.append(payload)
    return entries[-250:], alerts[-100:]


def _table_item(text: str, *, align: int = int(Qt.AlignLeft | Qt.AlignVCenter)) -> QTableWidgetItem:
    item = QTableWidgetItem(text)
    item.setFlags(item.flags() & ~Qt.ItemIsEditable)
    item.setTextAlignment(align)
    return item


def _format_peer_display(peer: dict[str, Any]) -> str:
    name = str(peer.get("name") or "peer")
    address = str(peer.get("address") or "unknown")
    port = peer.get("port")
    vlan_id = peer.get("vlan_id")
    trusted = "trusted" if peer.get("trusted") else "untrusted"
    vlan_text = f"vlan {vlan_id}" if vlan_id is not None else "no vlan"
    return f"{name} | {address}:{port} | {vlan_text} | {trusted}"


def _human_bytes(value: float) -> str:
    size = float(value)
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} GB"


def _severity_for_event(payload: dict[str, Any]) -> str:
    event_name = str(payload.get("event") or "event")
    if payload.get("alert"):
        if event_name in {"hmac_fail", "arp_spoof", "seq_error", "vlan_violation"}:
            return "HIGH"
        if event_name == "ttl_anomaly":
            return "MEDIUM"
        return "ALERT"
    return "INFO"


class DashboardWindow(QMainWindow):
    peers_loaded = pyqtSignal(object)
    local_addresses_loaded = pyqtSignal(object)
    tailscale_state_loaded = pyqtSignal(object)
    logs_loaded = pyqtSignal(object, object)
    status_changed = pyqtSignal(str)
    transfer_finished = pyqtSignal(str, int, int)
    transfer_failed = pyqtSignal(str)
    transfer_progress = pyqtSignal(int, int)
    receive_finished = pyqtSignal(str, int, int)
    receive_failed = pyqtSignal(str)

    def __init__(self, auto_refresh: bool = True) -> None:
        super().__init__()
        self._auto_refresh = auto_refresh
        self._peers: list[dict[str, Any]] = []
        self._all_log_entries: list[dict[str, Any]] = []
        self._all_alert_entries: list[dict[str, Any]] = []
        self._receive_thread: threading.Thread | None = None
        self._receive_cancel: threading.Event | None = None
        self._settings_base_dir: Path | None = None  # overridable in tests
        self._build_window()
        self._connect_signals()
        self._configure_refresh()
        if self._auto_refresh:
            self.refresh_peers()
        self.refresh_logs()

    def _build_window(self) -> None:
        self.setWindowTitle("SecureLink Dashboard")
        if ICON_PATH.exists():
            self.setWindowIcon(QIcon(str(ICON_PATH)))
        self._build_menu()
        self.resize(1480, 920)
        # Keep the minimum modest so the window fits smaller laptop screens;
        # the panels live in scroll areas and adapt instead of being clipped.
        self.setMinimumSize(900, 600)
        self._apply_styles()

        central_widget = QWidget(self)
        self.setCentralWidget(central_widget)
        root_layout = QVBoxLayout(central_widget)
        root_layout.setContentsMargins(16, 16, 16, 16)
        root_layout.setSpacing(12)

        header = QFrame(central_widget)
        header.setObjectName("HeaderCard")
        header_layout = QVBoxLayout(header)
        header_layout.setContentsMargins(18, 16, 18, 16)
        header_layout.setSpacing(4)

        title = QLabel("SecureLink")
        title_font = QFont()
        title_font.setPointSize(22)
        title_font.setBold(True)
        title.setFont(title_font)
        title.setObjectName("HeaderTitle")

        subtitle = QLabel(
            "Send and receive files securely across LAN, VLAN, VPN, and WAN."
        )
        subtitle.setObjectName("HeaderSubtitle")

        self.status_label = QLabel("Ready")
        self.status_label.setObjectName("StatusLabel")

        header_layout.addWidget(title)
        header_layout.addWidget(subtitle)
        header_layout.addWidget(self.status_label)

        # One focused task per tab keeps the window calm instead of showing
        # every panel and field at once.
        tabs = QTabWidget()
        tabs.setObjectName("MainTabs")
        tabs.setDocumentMode(True)

        tabs.addTab(self._tab_with(self._build_transfer_panel), "  Send  ")
        tabs.addTab(self._tab_with(self._build_receive_panel), "  Receive  ")
        tabs.addTab(self._tab_with(self._build_network_panel), "  Network  ")
        tabs.addTab(self._tab_with(self._build_activity_panels), "  Activity  ")
        tabs.addTab(self._tab_with(self._build_settings_panel), "  Settings  ")

        root_layout.addWidget(header)
        root_layout.addWidget(tabs, stretch=1)

        self.statusBar().showMessage("Ready")

    def _tab_with(self, builder) -> QWidget:
        """Build a panel into a scrollable tab page (so it adapts to small screens)."""
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(6, 10, 6, 6)
        layout.setSpacing(12)
        builder(layout)
        layout.addStretch(1)
        return self._scrollable(page)

    def _build_activity_panels(self, parent_layout: QVBoxLayout) -> None:
        self._build_log_panel(parent_layout)
        self._build_alert_panel(parent_layout)

    def _make_collapsible(self, title: str) -> tuple[QPushButton, QWidget]:
        """A click-to-expand header + hidden container for advanced options."""
        header = QPushButton(f"▸  {title}")
        header.setObjectName("CollapseHeader")
        header.setCheckable(True)
        header.setCursor(Qt.PointingHandCursor)
        container = QWidget()
        container.setVisible(False)

        def on_toggle(checked: bool) -> None:
            container.setVisible(checked)
            header.setText(("▾  " if checked else "▸  ") + title)

        header.toggled.connect(on_toggle)
        return header, container

    def _scrollable(self, content: QWidget) -> QScrollArea:
        """Wrap a panel column so it scrolls instead of clipping on small screens."""
        area = QScrollArea()
        area.setObjectName("PanelScroll")
        area.setWidgetResizable(True)
        area.setFrameShape(QFrame.NoFrame)
        area.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        area.setWidget(content)
        return area

    def showEvent(self, event) -> None:  # type: ignore[override]
        super().showEvent(event)
        # Gentle fade-in the first time the window appears.
        if not getattr(self, "_did_fade_in", False):
            self._did_fade_in = True
            self.setWindowOpacity(0.0)
            fade = QPropertyAnimation(self, b"windowOpacity", self)
            fade.setDuration(280)
            fade.setStartValue(0.0)
            fade.setEndValue(1.0)
            fade.setEasingCurve(QEasingCurve.OutCubic)
            fade.finished.connect(lambda: self.setWindowOpacity(1.0))
            fade.start()
            self._fade_anim = fade  # keep a reference so it isn't GC'd
            # Fail-safe: if animations are disabled or never tick, make sure the
            # window can never get stuck invisible.
            QTimer.singleShot(450, lambda: self.setWindowOpacity(1.0))

    def _start_pulse(self, widget: QWidget) -> None:
        """Loop a soft opacity pulse on a widget to signal ongoing activity."""
        anims = getattr(self, "_pulse_anims", None)
        if anims is None:
            anims = self._pulse_anims = {}
        if widget in anims:
            return
        effect = QGraphicsOpacityEffect(widget)
        widget.setGraphicsEffect(effect)
        anim = QPropertyAnimation(effect, b"opacity", self)
        anim.setDuration(1000)
        anim.setStartValue(1.0)
        anim.setKeyValueAt(0.5, 0.35)
        anim.setEndValue(1.0)
        anim.setLoopCount(-1)
        anim.start()
        anims[widget] = (anim, effect)

    def _stop_pulse(self, widget: QWidget) -> None:
        anims = getattr(self, "_pulse_anims", None) or {}
        entry = anims.pop(widget, None)
        if entry is not None:
            anim, _effect = entry
            anim.stop()
        widget.setGraphicsEffect(None)

    def _build_menu(self) -> None:
        help_menu = self.menuBar().addMenu("&Help")
        help_menu.addAction("User &Manual", lambda: self._show_doc("User Manual", "docs/MANUAL.md"))
        help_menu.addAction("&FAQ", lambda: self._show_doc("FAQ", "docs/FAQ.md"))
        help_menu.addSeparator()
        help_menu.addAction(
            "View on &GitHub",
            lambda: QDesktopServices.openUrl(QUrl("https://github.com/FirasBech/securelink")),
        )
        help_menu.addAction("&About SecureLink", self._show_about)

    def _show_doc(self, title: str, relative_path: str) -> None:
        path = Path(__file__).resolve().parents[1] / relative_path
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            text = f"# {title}\n\nCould not open `{relative_path}`."

        dialog = QDialog(self)
        dialog.setWindowTitle(f"SecureLink — {title}")
        dialog.resize(860, 680)
        layout = QVBoxLayout(dialog)
        layout.setContentsMargins(0, 0, 0, 0)
        browser = QTextBrowser(dialog)
        browser.setOpenExternalLinks(True)
        # Render as a clean light "page" regardless of the dark app theme.
        browser.setStyleSheet(
            "QTextBrowser { background: #ffffff; color: #1f2937; padding: 18px; }"
        )
        try:
            browser.setMarkdown(text)
        except AttributeError:  # Qt < 5.14 has no markdown renderer
            browser.setPlainText(text)
        layout.addWidget(browser)
        dialog.exec_()

    def _show_about(self) -> None:
        QMessageBox.about(
            self,
            "About SecureLink",
            "<b>SecureLink</b><br>"
            "Authenticated, encrypted file transfer for LAN, VLAN, and WAN.<br><br>"
            "AES-256-GCM · X25519 · Ed25519 / TOFU · reliable-UDP WAN transport.<br>"
            "A portfolio prototype — see the User Manual and FAQ under Help.<br><br>"
            '<a href="https://github.com/FirasBech/securelink">github.com/FirasBech/securelink</a>',
        )

    def _apply_styles(self) -> None:
        self.setStyleSheet(
            """
            QMainWindow {
                background: #0f172a;
            }
            QWidget {
                color: #e2e8f0;
                font-size: 13px;
            }
            QFrame#HeaderCard {
                background: #1e293b;
                border: 1px solid #334155;
                border-radius: 14px;
            }
            QLabel {
                color: #cbd5e1;
            }
            QLabel#HeaderTitle {
                color: #f8fafc;
            }
            QLabel#HeaderSubtitle {
                color: #94a3b8;
            }
            QLabel#StatusLabel {
                color: #38bdf8;
                font-weight: 600;
            }
            QLabel#ReceiveStatus, QLabel#LogSummary, QLabel#AlertSummary {
                color: #94a3b8;
            }
            QLabel#LocalAddresses {
                color: #cbd5e1;
                font-family: "Consolas", "Courier New", monospace;
            }
            QLabel#PanelHint {
                color: #94a3b8;
                font-size: 12px;
                font-weight: 400;
            }
            QLabel#TailscaleHint {
                color: #fbbf24;
                font-size: 12px;
                font-weight: 600;
                padding: 6px 8px;
                background: #422006;
                border: 1px solid #854d0e;
                border-radius: 8px;
            }
            QScrollArea#PanelScroll {
                background: transparent;
                border: none;
            }
            QScrollArea#PanelScroll > QWidget > QWidget {
                background: transparent;
            }
            QGroupBox {
                background: #1e293b;
                border: 1px solid #334155;
                border-radius: 12px;
                margin-top: 14px;
                padding: 10px;
                font-weight: 600;
                color: #e2e8f0;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 12px;
                padding: 0 6px;
                color: #cbd5e1;
            }
            QLineEdit, QComboBox, QSpinBox {
                background: #0f172a;
                color: #e2e8f0;
                border: 1px solid #334155;
                border-radius: 8px;
                padding: 6px 8px;
                selection-background-color: #2563eb;
            }
            QLineEdit:focus, QComboBox:focus, QSpinBox:focus {
                border: 1px solid #3b82f6;
            }
            QComboBox QAbstractItemView {
                background: #1e293b;
                color: #e2e8f0;
                selection-background-color: #2563eb;
            }
            QCheckBox {
                color: #cbd5e1;
                spacing: 6px;
            }
            QPushButton {
                background: #334155;
                color: #e2e8f0;
                border: none;
                border-radius: 8px;
                padding: 8px 14px;
                font-weight: 600;
            }
            QPushButton:hover {
                background: #475569;
            }
            QPushButton:pressed {
                background: #1e293b;
            }
            QPushButton:disabled {
                background: #1e293b;
                color: #64748b;
            }
            QPushButton#PrimaryButton {
                background: #2563eb;
                color: #ffffff;
                padding: 9px 18px;
            }
            QPushButton#PrimaryButton:hover {
                background: #3b82f6;
            }
            QPushButton#PrimaryButton:pressed {
                background: #1d4ed8;
            }
            QPushButton#PrimaryButton:disabled {
                background: #334155;
                color: #64748b;
            }
            QTableWidget {
                background: #1e293b;
                color: #e2e8f0;
                border: 1px solid #334155;
                border-radius: 8px;
                alternate-background-color: #172033;
                gridline-color: #334155;
                selection-background-color: #1d4ed8;
                selection-color: #ffffff;
            }
            QHeaderView::section {
                background: #111827;
                color: #cbd5e1;
                padding: 6px 8px;
                border: none;
                border-bottom: 1px solid #334155;
                font-weight: 600;
            }
            QProgressBar {
                border: 1px solid #334155;
                border-radius: 8px;
                background: #0f172a;
                color: #e2e8f0;
                text-align: center;
                height: 18px;
            }
            QProgressBar::chunk {
                border-radius: 8px;
                background: #3b82f6;
            }
            QStatusBar {
                color: #94a3b8;
            }
            QMenuBar {
                background: #0f172a;
                color: #cbd5e1;
            }
            QMenuBar::item {
                padding: 4px 10px;
                background: transparent;
            }
            QMenuBar::item:selected {
                background: #1e293b;
            }
            QMenu {
                background: #1e293b;
                color: #e2e8f0;
                border: 1px solid #334155;
            }
            QMenu::item:selected {
                background: #2563eb;
            }
            QSplitter::handle {
                background: #334155;
            }
            QTabWidget#MainTabs::pane {
                border: 1px solid #334155;
                border-radius: 12px;
                background: #1e293b;
                top: -1px;
            }
            QTabBar::tab {
                background: transparent;
                color: #94a3b8;
                padding: 9px 18px;
                margin-right: 4px;
                border: 1px solid transparent;
                border-top-left-radius: 10px;
                border-top-right-radius: 10px;
                font-weight: 600;
            }
            QTabBar::tab:hover {
                color: #e2e8f0;
            }
            QTabBar::tab:selected {
                background: #1e293b;
                color: #f8fafc;
                border-color: #334155;
                border-bottom-color: #1e293b;
            }
            QPushButton#CollapseHeader {
                background: transparent;
                color: #94a3b8;
                text-align: left;
                padding: 6px 4px;
                font-weight: 600;
            }
            QListWidget#ReceivedList {
                background: #0f172a;
                color: #e2e8f0;
                border: 1px solid #334155;
                border-radius: 8px;
                padding: 4px;
                outline: none;
            }
            QListWidget#ReceivedList::item {
                padding: 6px 8px;
                border-radius: 6px;
            }
            QListWidget#ReceivedList::item:selected {
                background: #1d4ed8;
                color: #ffffff;
            }
            QListWidget#ReceivedList::item:hover {
                background: #1e293b;
            }
            QPushButton#CollapseHeader:hover {
                color: #e2e8f0;
                background: transparent;
            }
            QPushButton#CollapseHeader:pressed {
                background: transparent;
            }
            QScrollBar:vertical {
                background: #0f172a;
                width: 12px;
                margin: 0;
            }
            QScrollBar::handle:vertical {
                background: #334155;
                border-radius: 6px;
                min-height: 24px;
            }
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
                height: 0;
            }
            QScrollBar:horizontal {
                background: #0f172a;
                height: 12px;
                margin: 0;
            }
            QScrollBar::handle:horizontal {
                background: #334155;
                border-radius: 6px;
                min-width: 24px;
            }
            QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
                width: 0;
            }
            """
        )

    def _configure_refresh(self) -> None:
        self._log_timer = QTimer(self)
        self._log_timer.setInterval(5000)
        self._log_timer.timeout.connect(self.refresh_logs)
        if self._auto_refresh:
            self._log_timer.start()

    def _connect_signals(self) -> None:
        self.peers_loaded.connect(self._render_peers)
        self.local_addresses_loaded.connect(self._render_local_addresses)
        self.tailscale_state_loaded.connect(self._render_tailscale_state)
        self.logs_loaded.connect(self._render_logs)
        self.status_changed.connect(self._set_status)
        self.transfer_finished.connect(self._on_transfer_finished)
        self.transfer_failed.connect(self._on_transfer_failed)
        self.transfer_progress.connect(self._on_transfer_progress)
        self.receive_finished.connect(self._on_receive_finished)
        self.receive_failed.connect(self._on_receive_failed)

    def _build_transfer_panel(self, parent_layout: QVBoxLayout) -> None:
        hint = QLabel("1. Pick a file   2. Choose a device or type its address   3. Send File")
        hint.setObjectName("PanelHint")
        hint.setWordWrap(True)
        parent_layout.addWidget(hint)

        grid = QGridLayout()
        grid.setHorizontalSpacing(10)
        grid.setVerticalSpacing(10)
        grid.setColumnStretch(1, 1)
        grid.setColumnStretch(3, 1)

        self.file_edit = QLineEdit()
        self.file_edit.setPlaceholderText("Choose a file to send")
        self.file_edit.setToolTip("The file you want to send.")
        browse_button = QPushButton("Browse")
        browse_button.clicked.connect(self.choose_file)
        browse_button.setToolTip("Pick the file to send.")

        self.peer_selector = QComboBox()
        self.peer_selector.currentIndexChanged.connect(self._apply_selected_peer)
        self.peer_selector.setPlaceholderText("Discover peers")
        self.peer_selector.setToolTip(
            "Devices found on your network. Pick one to fill in its address automatically."
        )

        self.peer_host_edit = QLineEdit()
        self.peer_host_edit.setPlaceholderText("e.g. 192.168.1.20 or a 100.x VPN address")
        self.peer_host_edit.setToolTip(
            "The receiver's IP address or hostname. On the same Wi-Fi/LAN use their "
            "192.168.x address; on a VPN use their 100.x (Tailscale) address."
        )

        self.peer_port_spin = QSpinBox()
        self.peer_port_spin.setRange(1, 65535)
        self.peer_port_spin.setValue(55000)
        self.peer_port_spin.setToolTip("The port the receiver is listening on (default 55000).")

        grid.addWidget(QLabel("File"), 0, 0)
        grid.addWidget(self.file_edit, 0, 1, 1, 2)
        grid.addWidget(browse_button, 0, 3)

        grid.addWidget(QLabel("Device"), 1, 0)
        grid.addWidget(self.peer_selector, 1, 1, 1, 3)

        grid.addWidget(QLabel("Address"), 2, 0)
        grid.addWidget(self.peer_host_edit, 2, 1)
        grid.addWidget(QLabel("Port"), 2, 2)
        grid.addWidget(self.peer_port_spin, 2, 3)
        parent_layout.addLayout(grid)

        # Advanced options — collapsed by default so beginners aren't overwhelmed.
        self.mode_combo = QComboBox()
        self.mode_combo.addItems(["Auto", "LAN", "VLAN", "WAN", "VPN"])
        self.mode_combo.setToolTip(
            "How to reach the peer. Leave on Auto unless you know you need a specific "
            "mode: LAN/VLAN/VPN use direct TCP, WAN uses reliable UDP across the internet."
        )
        self.mtu_spin = QSpinBox()
        self.mtu_spin.setRange(576, 9000)
        self.mtu_spin.setValue(1500)
        self.mtu_spin.setToolTip(
            "Largest packet size in bytes. Leave at 1500 for normal networks."
        )
        self.vlan_spin = QSpinBox()
        self.vlan_spin.setRange(0, 4094)
        self.vlan_spin.setValue(0)
        self.vlan_spin.setSpecialValueText("None")
        self.vlan_spin.setToolTip(
            "Tag the transfer with a VLAN id for policy checks. Leave as None."
        )
        self.allow_unknown_checkbox = QCheckBox("Allow unknown devices (first contact)")
        self.allow_unknown_checkbox.setToolTip(
            "Tick this the first time you connect to a new device to trust its identity. "
            "After that it's remembered, and a changed identity is refused."
        )
        self.send_token_edit = QLineEdit()
        self.send_token_edit.setPlaceholderText("shared word, to send over the internet")
        self.send_token_edit.setToolTip(
            "To send over the internet via your coordination server (set it on the "
            "Settings tab), enter a token and have the receiver use the same one. The "
            "Address/Port above are ignored. Leave blank for local/VPN transfers."
        )

        adv_header, adv_box = self._make_collapsible("Advanced options")
        adv_grid = QGridLayout(adv_box)
        adv_grid.setContentsMargins(4, 4, 4, 4)
        adv_grid.setColumnStretch(1, 1)
        adv_grid.setColumnStretch(3, 1)
        adv_grid.addWidget(QLabel("Mode"), 0, 0)
        adv_grid.addWidget(self.mode_combo, 0, 1)
        adv_grid.addWidget(QLabel("MTU"), 0, 2)
        adv_grid.addWidget(self.mtu_spin, 0, 3)
        adv_grid.addWidget(QLabel("VLAN ID"), 1, 0)
        adv_grid.addWidget(self.vlan_spin, 1, 1)
        adv_grid.addWidget(self.allow_unknown_checkbox, 1, 2, 1, 2)
        adv_grid.addWidget(QLabel("Internet token"), 2, 0)
        adv_grid.addWidget(self.send_token_edit, 2, 1, 1, 3)
        parent_layout.addWidget(adv_header)
        parent_layout.addWidget(adv_box)

        self.refresh_peers_button = QPushButton("Refresh Peers")
        self.refresh_peers_button.clicked.connect(self.refresh_peers)
        self.refresh_peers_button.setToolTip("Search the network again for devices.")

        self.send_button = QPushButton("Send File")
        self.send_button.setObjectName("PrimaryButton")
        self.send_button.clicked.connect(self.send_selected_file)
        self.send_button.setToolTip("Encrypt and send the chosen file to the peer.")

        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.transfer_detail_label = QLabel("Idle")
        self.transfer_detail_label.setObjectName("TransferDetails")

        button_row = QHBoxLayout()
        button_row.addWidget(self.refresh_peers_button)
        button_row.addStretch(1)
        button_row.addWidget(self.send_button)
        parent_layout.addLayout(button_row)
        parent_layout.addWidget(self.progress_bar)
        parent_layout.addWidget(self.transfer_detail_label)

    def _build_receive_panel(self, parent_layout: QVBoxLayout) -> None:
        hint = QLabel("Click Start Listening, then give the sender your address shown below.")
        hint.setObjectName("PanelHint")
        hint.setWordWrap(True)
        parent_layout.addWidget(hint)

        grid = QGridLayout()
        grid.setHorizontalSpacing(10)
        grid.setVerticalSpacing(10)
        grid.setColumnStretch(1, 1)

        self.recv_port_spin = QSpinBox()
        self.recv_port_spin.setRange(1, 65535)
        self.recv_port_spin.setValue(55000)
        self.recv_port_spin.setToolTip(
            "The port to listen on. Tell the sender to use this same port (default 55000)."
        )

        self.recv_output_edit = QLineEdit(str(Path.cwd()))
        self.recv_output_edit.setToolTip("Folder where received files are saved.")
        recv_browse_button = QPushButton("Browse")
        recv_browse_button.clicked.connect(self.choose_output_dir)
        recv_browse_button.setToolTip("Choose the download folder.")

        self.local_addr_label = QLabel("Detecting addresses...")
        self.local_addr_label.setObjectName("LocalAddresses")
        self.local_addr_label.setWordWrap(True)
        self.local_addr_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.local_addr_label.setToolTip(
            "Addresses this machine is reachable on. Give one to the sender; "
            "prefer the VPN address when both of you are on the same VPN."
        )

        grid.addWidget(QLabel("Port"), 0, 0)
        grid.addWidget(self.recv_port_spin, 0, 1)

        grid.addWidget(QLabel("Save to"), 1, 0)
        grid.addWidget(self.recv_output_edit, 1, 1, 1, 2)
        grid.addWidget(recv_browse_button, 1, 3)

        grid.addWidget(QLabel("Your address"), 2, 0)
        grid.addWidget(self.local_addr_label, 2, 1, 1, 3)
        parent_layout.addLayout(grid)

        # Advanced options — collapsed by default.
        self.recv_wan_checkbox = QCheckBox("WAN (reliable UDP)")
        self.recv_wan_checkbox.setToolTip(
            "Tick this only if the sender is connecting over the internet (WAN). "
            "Leave unticked for the same network or a VPN."
        )
        self.recv_allowlist_edit = QLineEdit()
        self.recv_allowlist_edit.setPlaceholderText("Allowlist, e.g. 192.168.1.0/24, 10.0.0.5")
        self.recv_allowlist_edit.setToolTip(
            "Optional: only accept connections from these IPs or subnets (comma-separated). "
            "Leave empty to accept any."
        )
        self.recv_allow_unknown_checkbox = QCheckBox("Allow unknown devices (first contact)")
        self.recv_allow_unknown_checkbox.setToolTip(
            "Tick this for a first-time sender to trust its identity (remembered afterwards)."
        )
        self.recv_token_edit = QLineEdit()
        self.recv_token_edit.setPlaceholderText("shared word, to receive over the internet")
        self.recv_token_edit.setToolTip(
            "To receive over the internet via your coordination server (set it on the "
            "Settings tab), enter the same token the sender uses. Leave blank for "
            "local/VPN transfers."
        )

        adv_header, adv_box = self._make_collapsible("Advanced options")
        adv_grid = QGridLayout(adv_box)
        adv_grid.setContentsMargins(4, 4, 4, 4)
        adv_grid.setColumnStretch(1, 1)
        adv_grid.addWidget(self.recv_wan_checkbox, 0, 0, 1, 2)
        adv_grid.addWidget(QLabel("Allowlist"), 1, 0)
        adv_grid.addWidget(self.recv_allowlist_edit, 1, 1)
        adv_grid.addWidget(self.recv_allow_unknown_checkbox, 2, 0, 1, 2)
        adv_grid.addWidget(QLabel("Internet token"), 3, 0)
        adv_grid.addWidget(self.recv_token_edit, 3, 1)
        parent_layout.addWidget(adv_header)
        parent_layout.addWidget(adv_box)

        self.receive_button = QPushButton("Start Listening")
        self.receive_button.setObjectName("PrimaryButton")
        self.receive_button.clicked.connect(self.toggle_receiving)
        self.receive_button.setToolTip("Start listening for one incoming file.")

        self.receive_status_label = QLabel("Idle")
        self.receive_status_label.setObjectName("ReceiveStatus")

        button_row = QHBoxLayout()
        button_row.addWidget(self.receive_button)
        button_row.addWidget(self.receive_status_label, 1)
        parent_layout.addLayout(button_row)

        # Received-files list: what arrived, where, with the OS file-type icon.
        received_row = QHBoxLayout()
        received_header = QLabel("Received files")
        received_header.setObjectName("PanelHint")
        received_row.addWidget(received_header)
        received_row.addStretch(1)
        open_folder_button = QPushButton("Open download folder")
        open_folder_button.clicked.connect(self._open_download_folder)
        open_folder_button.setToolTip("Open the folder where received files are saved.")
        received_row.addWidget(open_folder_button)
        parent_layout.addLayout(received_row)

        self._icon_provider = QFileIconProvider()
        self.received_list = QListWidget()
        self.received_list.setObjectName("ReceivedList")
        self.received_list.setIconSize(QSize(28, 28))
        self.received_list.setMinimumHeight(150)
        self.received_list.setToolTip("Double-click a file to open it.")
        self.received_list.itemDoubleClicked.connect(self._open_received_item)
        self._received_empty_hint = QListWidgetItem("Received files will appear here.")
        self._received_empty_hint.setFlags(Qt.NoItemFlags)
        self.received_list.addItem(self._received_empty_hint)
        parent_layout.addWidget(self.received_list)

    def _open_download_folder(self) -> None:
        folder = self.recv_output_edit.text().strip() or str(Path.cwd())
        QDesktopServices.openUrl(QUrl.fromLocalFile(folder))

    def _open_received_item(self, item: QListWidgetItem) -> None:
        path = item.data(Qt.UserRole)
        if path:
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(path)))

    def _add_received_file(self, path: str) -> None:
        # Drop the "appear here" placeholder on the first real entry.
        if self._received_empty_hint is not None:
            row = self.received_list.row(self._received_empty_hint)
            if row >= 0:
                self.received_list.takeItem(row)
            self._received_empty_hint = None

        file_path = Path(path)
        icon = self._icon_provider.icon(QFileInfo(str(file_path)))
        try:
            size = file_path.stat().st_size
        except OSError:
            size = 0
        when = datetime.now().strftime("%H:%M")
        item = QListWidgetItem(icon, f"{file_path.name}    {_human_bytes(size)} · {when}")
        item.setData(Qt.UserRole, str(file_path))
        item.setToolTip(str(file_path))
        self.received_list.insertItem(0, item)  # newest on top
        self.received_list.setCurrentRow(0)

    def choose_output_dir(self) -> None:
        directory = QFileDialog.getExistingDirectory(
            self,
            "Select download directory",
            self.recv_output_edit.text().strip() or str(Path.cwd()),
        )
        if directory:
            self.recv_output_edit.setText(directory)

    def toggle_receiving(self) -> None:
        if self._receive_thread is not None and self._receive_thread.is_alive():
            if self._receive_cancel is not None:
                self._receive_cancel.set()
            self.receive_button.setEnabled(False)
            self.receive_status_label.setText("Stopping...")
            return

        output_dir = self.recv_output_edit.text().strip() or str(Path.cwd())
        allowlist = tuple(
            entry.strip()
            for entry in self.recv_allowlist_edit.text().split(",")
            if entry.strip()
        )

        # Internet transfer via a coordination server takes precedence when a
        # token is given.
        token = self.recv_token_edit.text().strip()
        if token:
            self._receive_over_internet(token, output_dir, allowlist)
            return

        wan = self.recv_wan_checkbox.isChecked()
        config = TransportConfig(
            mode="wan" if wan else "lan",
            port=self.recv_port_spin.value(),
            allow_unknown=self.recv_allow_unknown_checkbox.isChecked(),
            allowlist=allowlist,
            output_dir=Path(output_dir),
        )
        cancel = threading.Event()
        self._receive_cancel = cancel

        self.receive_button.setText("Stop")
        self.receive_status_label.setText(
            f"Listening on :{config.port} ({config.mode.upper()})..."
        )
        self._start_pulse(self.receive_status_label)
        self.status_changed.emit(f"Listening for a file on :{config.port}")

        def _worker() -> None:
            try:
                if wan:
                    output_path, stats = udp_receive_file(config=config, cancel_event=cancel)
                else:
                    output_path, stats = receive_file(config=config, cancel_event=cancel)
            except Exception as exc:
                self.receive_failed.emit(str(exc))
                return
            self.receive_finished.emit(str(output_path), stats.bytes_transferred, stats.chunks)

        self._receive_thread = threading.Thread(target=_worker, daemon=True)
        self._receive_thread.start()

    def _receive_over_internet(self, token: str, output_dir: str, allowlist: tuple[str, ...]) -> None:
        resolved = self._coordination_settings()
        if resolved is None:
            self.receive_status_label.setText("Set a Rendezvous server in Settings")
            QMessageBox.warning(
                self,
                "SecureLink",
                "To receive over the internet, set a Rendezvous server in the Settings tab "
                "first (or clear the Internet token).",
            )
            return
        if resolved[0] == "error":
            QMessageBox.warning(self, "SecureLink", f"Invalid coordination server: {resolved[1]}")
            return
        rendezvous_addr, relay_addr, stun_kwargs = resolved

        config = TransportConfig(
            mode="wan",
            allow_unknown=self.recv_allow_unknown_checkbox.isChecked(),
            allowlist=allowlist,
            output_dir=Path(output_dir),
        )
        cancel = threading.Event()
        self._receive_cancel = cancel

        self.receive_button.setText("Stop")
        self.receive_status_label.setText("Connecting via coordination server...")
        self._start_pulse(self.receive_status_label)
        self.status_changed.emit("Waiting for an internet transfer...")

        def _worker() -> None:
            try:
                output_path, stats = wan_receive_file(
                    rendezvous_addr=rendezvous_addr,
                    token=token,
                    relay_addr=relay_addr,
                    config=config,
                    cancel_event=cancel,
                    base_dir=self._settings_base_dir,
                    **stun_kwargs,
                )
            except Exception as exc:
                self.receive_failed.emit(str(exc))
                return
            self.receive_finished.emit(str(output_path), stats.bytes_transferred, stats.chunks)

        self._receive_thread = threading.Thread(target=_worker, daemon=True)
        self._receive_thread.start()

    def _reset_receive_button(self) -> None:
        self._stop_pulse(self.receive_status_label)
        self.receive_button.setText("Start Listening")
        self.receive_button.setEnabled(True)

    def _on_receive_finished(self, path: str, bytes_received: int, chunks: int) -> None:
        self._reset_receive_button()
        name = Path(path).name
        self.receive_status_label.setText(
            f"Received {name} ({_human_bytes(bytes_received)}, {chunks} chunk(s))"
        )
        self._add_received_file(path)
        self.status_changed.emit(f"Received {name}")
        self.refresh_logs()

    def _on_receive_failed(self, message: str) -> None:
        self._reset_receive_button()
        if "cancel" in message.lower():
            self.receive_status_label.setText("Stopped")
            self.status_changed.emit("Receive stopped")
            return
        self.receive_status_label.setText("Receive failed")
        self.status_changed.emit("Receive failed")
        QMessageBox.critical(self, "SecureLink", message)

    def _build_network_panel(self, parent_layout: QVBoxLayout) -> None:
        group = QGroupBox("Devices on Your Network")
        layout = QVBoxLayout(group)
        layout.setContentsMargins(10, 10, 10, 10)

        self.network_table = QTableWidget(0, 6)
        self.network_table.setHorizontalHeaderLabels(
            ["Name", "Address", "Port", "VLAN", "Trusted", "Source"]
        )
        self.network_table.setAlternatingRowColors(True)
        self.network_table.setSelectionBehavior(self.network_table.SelectRows)
        self.network_table.setSelectionMode(self.network_table.SingleSelection)
        self.network_table.verticalHeader().setVisible(False)
        self.network_table.horizontalHeader().setStretchLastSection(True)
        self.network_table.itemSelectionChanged.connect(self._apply_selected_network_row)
        self.network_table.setToolTip("Click a device to fill in its address in the Send panel above.")

        self.network_hint_label = QLabel(
            "No devices found yet. Click Refresh Peers, or just type the address in the Send panel."
        )
        self.network_hint_label.setObjectName("PanelHint")
        self.network_hint_label.setWordWrap(True)

        # Surfaces Tailscale credential/login state (each user must sign in once).
        self.tailscale_hint_label = QLabel()
        self.tailscale_hint_label.setObjectName("TailscaleHint")
        self.tailscale_hint_label.setWordWrap(True)
        self.tailscale_hint_label.setVisible(False)

        layout.addWidget(self.network_table)
        layout.addWidget(self.network_hint_label)
        layout.addWidget(self.tailscale_hint_label)
        parent_layout.addWidget(group, stretch=1)

    def _build_log_panel(self, parent_layout: QVBoxLayout) -> None:
        group = QGroupBox("Activity Log")
        layout = QVBoxLayout(group)
        layout.setContentsMargins(10, 10, 10, 10)

        header_row = QHBoxLayout()
        self.log_refresh_button = QPushButton("Refresh Logs")
        self.log_refresh_button.clicked.connect(self.refresh_logs)
        self.log_refresh_button.setToolTip("Reload today's activity log.")
        self.log_search_edit = QLineEdit()
        self.log_search_edit.setPlaceholderText("Filter logs…")
        self.log_search_edit.setClearButtonEnabled(True)
        self.log_search_edit.textChanged.connect(self._apply_log_filter)
        self.log_search_edit.setToolTip("Type to show only log rows containing this text.")
        self.log_alerts_only_checkbox = QCheckBox("Alerts only")
        self.log_alerts_only_checkbox.stateChanged.connect(self._apply_log_filter)
        self.log_alerts_only_checkbox.setToolTip("Show only security alerts.")
        self.log_summary_label = QLabel("0 events, 0 alerts")
        self.log_summary_label.setObjectName("LogSummary")
        header_row.addWidget(self.log_refresh_button)
        header_row.addWidget(self.log_search_edit, 1)
        header_row.addWidget(self.log_alerts_only_checkbox)
        header_row.addWidget(self.log_summary_label)

        self.log_table = QTableWidget(0, 9)
        self.log_table.setHorizontalHeaderLabels(
            ["Timestamp", "Event", "Src IP", "Dst IP", "VLAN", "Bytes", "Chunk", "Alert", "Message"]
        )
        self.log_table.setAlternatingRowColors(True)
        self.log_table.setSelectionBehavior(self.log_table.SelectRows)
        self.log_table.setSelectionMode(self.log_table.SingleSelection)
        self.log_table.verticalHeader().setVisible(False)
        self.log_table.horizontalHeader().setStretchLastSection(True)

        layout.addLayout(header_row)
        layout.addWidget(self.log_table)
        parent_layout.addWidget(group, stretch=2)

    def _build_alert_panel(self, parent_layout: QVBoxLayout) -> None:
        group = QGroupBox("Security Alerts")
        layout = QVBoxLayout(group)
        layout.setContentsMargins(10, 10, 10, 10)

        self.alert_summary_label = QLabel("0 active alerts")
        self.alert_summary_label.setObjectName("AlertSummary")

        self.alert_table = QTableWidget(0, 4)
        self.alert_table.setHorizontalHeaderLabels(["Severity", "Event", "Source", "Message"])
        self.alert_table.setAlternatingRowColors(True)
        self.alert_table.setSelectionBehavior(self.alert_table.SelectRows)
        self.alert_table.setSelectionMode(self.alert_table.SingleSelection)
        self.alert_table.verticalHeader().setVisible(False)
        self.alert_table.horizontalHeader().setStretchLastSection(True)

        layout.addWidget(self.alert_summary_label)
        layout.addWidget(self.alert_table)
        parent_layout.addWidget(group, stretch=1)

    def _build_settings_panel(self, parent_layout: QVBoxLayout) -> None:
        intro = QLabel(
            "SecureLink uses no server of its own and phones home to nothing. LAN, VLAN "
            "and VPN transfers are fully peer-to-peer. For internet (WAN) transfers "
            "through NATs you can optionally run your OWN coordination servers and point "
            "SecureLink at them below — leave everything blank to skip."
        )
        intro.setObjectName("PanelHint")
        intro.setWordWrap(True)
        parent_layout.addWidget(intro)

        group = QGroupBox("Coordination servers — bring your own (optional)")
        grid = QGridLayout(group)
        grid.setHorizontalSpacing(10)
        grid.setVerticalSpacing(10)
        grid.setColumnStretch(1, 1)

        self.set_rendezvous_edit = QLineEdit()
        self.set_rendezvous_edit.setPlaceholderText("host:port (optional)")
        self.set_rendezvous_edit.setToolTip(
            "A rendezvous server you host (python -m ui.cli rendezvous). It pairs two "
            "peers by token so they can hole punch. Leave blank to not use one."
        )
        self.set_relay_edit = QLineEdit()
        self.set_relay_edit.setPlaceholderText("host:port (optional)")
        self.set_relay_edit.setToolTip(
            "A relay server you host (python -m ui.cli relay), used as a fallback when "
            "hole punching fails (symmetric NAT). Optional."
        )
        self.set_stun_host_edit = QLineEdit()
        self.set_stun_host_edit.setPlaceholderText("stun.l.google.com (default)")
        self.set_stun_host_edit.setToolTip(
            "STUN server used only to learn your public address. Defaults to a public "
            "one; override if you prefer your own."
        )
        self.set_stun_port_spin = QSpinBox()
        self.set_stun_port_spin.setRange(0, 65535)
        self.set_stun_port_spin.setValue(0)
        self.set_stun_port_spin.setSpecialValueText("default")
        self.set_stun_port_spin.setToolTip("STUN port (0 = default 19302).")

        grid.addWidget(QLabel("Rendezvous"), 0, 0)
        grid.addWidget(self.set_rendezvous_edit, 0, 1, 1, 3)
        grid.addWidget(QLabel("Relay"), 1, 0)
        grid.addWidget(self.set_relay_edit, 1, 1, 1, 3)
        grid.addWidget(QLabel("STUN host"), 2, 0)
        grid.addWidget(self.set_stun_host_edit, 2, 1)
        grid.addWidget(QLabel("STUN port"), 2, 2)
        grid.addWidget(self.set_stun_port_spin, 2, 3)
        parent_layout.addWidget(group)

        self.set_save_button = QPushButton("Save Settings")
        self.set_save_button.setObjectName("PrimaryButton")
        self.set_save_button.clicked.connect(self._save_settings)
        self.settings_status_label = QLabel("")
        self.settings_status_label.setObjectName("ReceiveStatus")
        row = QHBoxLayout()
        row.addWidget(self.set_save_button)
        row.addWidget(self.settings_status_label, 1)
        parent_layout.addLayout(row)

        howto = QLabel(
            "Host your own on a public machine:  python -m ui.cli rendezvous --port 6000  "
            "and  python -m ui.cli relay --port 6001 . Then both peers use the same token."
        )
        howto.setObjectName("PanelHint")
        howto.setWordWrap(True)
        parent_layout.addWidget(howto)

        self._load_settings_into_form()

    def _load_settings_into_form(self) -> None:
        settings = Settings.load(self._settings_base_dir)
        self.set_rendezvous_edit.setText(settings.rendezvous or "")
        self.set_relay_edit.setText(settings.relay or "")
        self.set_stun_host_edit.setText(settings.stun_host or "")
        self.set_stun_port_spin.setValue(settings.stun_port or 0)

    def _save_settings(self) -> None:
        rendezvous = self.set_rendezvous_edit.text().strip()
        relay = self.set_relay_edit.text().strip()
        try:
            if rendezvous:
                parse_host_port(rendezvous)
            if relay:
                parse_host_port(relay)
        except SettingsError as exc:
            self.settings_status_label.setText("Invalid address")
            QMessageBox.warning(self, "SecureLink", f"Invalid server address: {exc}")
            return
        settings = Settings(
            rendezvous=rendezvous or None,
            relay=relay or None,
            stun_host=self.set_stun_host_edit.text().strip() or None,
            stun_port=self.set_stun_port_spin.value() or None,
        )
        try:
            settings.save(self._settings_base_dir)
        except OSError as exc:
            self.settings_status_label.setText("Could not save")
            QMessageBox.critical(self, "SecureLink", f"Could not save settings: {exc}")
            return
        self.settings_status_label.setText("Saved")
        self.status_changed.emit("Settings saved")

    def choose_file(self) -> None:
        file_path, _selected_filter = QFileDialog.getOpenFileName(
            self,
            "Select file to send",
            str(Path.cwd()),
            "All Files (*)",
        )
        if file_path:
            self.file_edit.setText(file_path)

    def refresh_peers(self) -> None:
        self.status_changed.emit("Discovering peers...")
        assumed_port = self.peer_port_spin.value()

        def _worker() -> None:
            peer_records: list[dict[str, Any]] = []
            try:
                peer_records = [dict(vars(peer)) for peer in discover_peers()]
            except Exception as exc:
                self.status_changed.emit(f"Peer discovery unavailable: {exc}")
            # Tailscale (best-effort): one status read shared by peers + login check.
            ts_status = None
            try:
                from core.discovery import tailscale_status

                ts_status = tailscale_status()
                seen = {record.get("address") for record in peer_records}
                for peer in tailscale_peers(port=assumed_port, status=ts_status):
                    if peer.address not in seen:
                        peer_records.append(dict(vars(peer)))
                        seen.add(peer.address)
            except Exception:
                pass
            self.peers_loaded.emit(peer_records)
            try:
                self.local_addresses_loaded.emit(
                    [dict(vars(addr)) for addr in local_reachable_addresses()]
                )
            except Exception:
                pass
            try:
                self.tailscale_state_loaded.emit(
                    {"summary": tailscale_state(status=ts_status).summary()}
                )
            except Exception:
                pass

        threading.Thread(target=_worker, daemon=True).start()

    def _render_tailscale_state(self, payload: object) -> None:
        summary = str(payload.get("summary") or "") if isinstance(payload, dict) else ""
        self.tailscale_hint_label.setText(summary)
        self.tailscale_hint_label.setVisible(bool(summary))

    def _render_local_addresses(self, payload: object) -> None:
        addresses = payload if isinstance(payload, list) else []
        if not addresses:
            self.local_addr_label.setText("No reachable address detected")
            return
        labels = {"vpn": "VPN", "lan": "LAN", "public": "public"}
        parts = [
            f"{addr.get('address')} ({labels.get(addr.get('kind'), addr.get('kind'))})"
            for addr in addresses
            if addr.get("address")
        ]
        self.local_addr_label.setText("    ".join(parts))

    def _render_peers(self, peers: object) -> None:
        self._peers = list(peers) if isinstance(peers, list) else []

        self.peer_selector.blockSignals(True)
        self.peer_selector.clear()
        for peer in self._peers:
            self.peer_selector.addItem(_format_peer_display(peer), peer)
        self.peer_selector.blockSignals(False)

        if self._peers:
            self.peer_selector.setCurrentIndex(0)
            self._apply_selected_peer(0)
        else:
            self.peer_host_edit.clear()
            self.peer_port_spin.setValue(55000)

        self._render_network_table(self._peers)
        self.statusBar().showMessage(f"Discovered {len(self._peers)} peer(s)")

    def _render_network_table(self, peers: list[dict[str, Any]]) -> None:
        self.network_hint_label.setVisible(len(peers) == 0)
        self.network_table.setRowCount(len(peers))
        for row, peer in enumerate(peers):
            values = [
                str(peer.get("name") or "peer"),
                str(peer.get("address") or ""),
                str(peer.get("port") or ""),
                "" if peer.get("vlan_id") is None else str(peer.get("vlan_id")),
                "Yes" if peer.get("trusted") else "No",
                str(peer.get("source") or "mdns"),
            ]
            for column, value in enumerate(values):
                item = _table_item(value)
                if column == 0:
                    item.setData(Qt.UserRole, peer)
                self.network_table.setItem(row, column, item)

        self._resize_table_columns(self.network_table, stretch_last=True)

    def _apply_selected_peer(self, index: int) -> None:
        peer = self.peer_selector.itemData(index)
        if not isinstance(peer, dict):
            return
        if peer.get("address"):
            self.peer_host_edit.setText(str(peer.get("address")))
        if peer.get("port"):
            self.peer_port_spin.setValue(int(peer.get("port")))
        if peer.get("vlan_id") is not None:
            self.vlan_spin.setValue(int(peer.get("vlan_id")))

    def _apply_selected_network_row(self) -> None:
        selected_rows = self.network_table.selectionModel().selectedRows()
        if not selected_rows:
            return
        row = selected_rows[0].row()
        item = self.network_table.item(row, 0)
        if item is None:
            return
        peer = item.data(Qt.UserRole)
        if isinstance(peer, dict):
            if peer.get("address"):
                self.peer_host_edit.setText(str(peer.get("address")))
            if peer.get("port"):
                self.peer_port_spin.setValue(int(peer.get("port")))
            if peer.get("vlan_id") is not None:
                self.vlan_spin.setValue(int(peer.get("vlan_id")))

    def refresh_logs(self) -> None:
        entries, alerts = _read_today_log_entries()
        self.logs_loaded.emit(entries, alerts)

    def _render_logs(self, payload: object, alerts: object) -> None:
        self._all_log_entries = [
            e for e in (payload if isinstance(payload, list) else []) if isinstance(e, dict)
        ]
        self._all_alert_entries = [
            e for e in (alerts if isinstance(alerts, list) else []) if isinstance(e, dict)
        ]

        self.alert_summary_label.setText(f"{len(self._all_alert_entries)} active alerts")
        self.alert_table.setRowCount(len(self._all_alert_entries))
        for row, entry in enumerate(self._all_alert_entries):
            severity = _severity_for_event(entry)
            values = [
                severity,
                str(entry.get("event") or ""),
                str(entry.get("src_ip") or entry.get("peer_ip") or ""),
                str(entry.get("message") or ""),
            ]
            for column, value in enumerate(values):
                item = _table_item(value)
                item.setToolTip(json.dumps(entry, sort_keys=True))
                if severity == "HIGH":
                    item.setBackground(QColor("#450a0a"))
                    item.setForeground(QColor("#fecaca"))
                elif severity == "MEDIUM":
                    item.setBackground(QColor("#422006"))
                    item.setForeground(QColor("#fde68a"))
                self.alert_table.setItem(row, column, item)
        self._resize_table_columns(self.alert_table, stretch_last=True)

        self._apply_log_filter()

    def _apply_log_filter(self) -> None:
        query = self.log_search_edit.text().strip().lower()
        alerts_only = self.log_alerts_only_checkbox.isChecked()

        def _matches(entry: dict[str, Any]) -> bool:
            if alerts_only and not entry.get("alert"):
                return False
            if not query:
                return True
            return query in " ".join(str(v) for v in entry.values()).lower()

        entries = [entry for entry in self._all_log_entries if _matches(entry)]
        self.log_summary_label.setText(
            f"{len(entries)} / {len(self._all_log_entries)} events, "
            f"{len(self._all_alert_entries)} alerts"
        )

        self.log_table.setRowCount(len(entries))
        for row, entry in enumerate(entries):
            values = [
                str(entry.get("timestamp") or ""),
                str(entry.get("event") or ""),
                str(entry.get("src_ip") or ""),
                str(entry.get("dst_ip") or ""),
                "" if entry.get("vlan_id") is None else str(entry.get("vlan_id")),
                "" if entry.get("bytes") is None else str(entry.get("bytes")),
                "" if entry.get("chunk_id") is None else str(entry.get("chunk_id")),
                "Yes" if entry.get("alert") else "No",
                str(entry.get("message") or ""),
            ]
            alert = bool(entry.get("alert"))
            for column, value in enumerate(values):
                item = _table_item(value)
                item.setToolTip(json.dumps(entry, sort_keys=True))
                if alert:
                    item.setBackground(QColor("#450a0a"))
                    item.setForeground(QColor("#fecaca"))
                self.log_table.setItem(row, column, item)

        self._resize_table_columns(self.log_table, stretch_last=True)

    def _reject_send(self, message: str) -> None:
        self.transfer_detail_label.setText(message)
        self.status_changed.emit(message)
        QMessageBox.warning(self, "SecureLink", message)

    def send_selected_file(self) -> None:
        file_path = self.file_edit.text().strip()
        if not file_path:
            self._reject_send("Choose a file before sending.")
            return
        if not Path(file_path).is_file():
            self._reject_send(f"File not found: {file_path}")
            return

        # Internet transfer via a coordination server takes precedence when a
        # token is given (the peer address is then irrelevant).
        token = self.send_token_edit.text().strip()
        if token:
            self._send_over_internet(file_path, token)
            return

        peer_host = self.peer_host_edit.text().strip()
        if not peer_host and self.peer_selector.currentIndex() >= 0:
            peer = self.peer_selector.currentData()
            if isinstance(peer, dict):
                peer_host = str(peer.get("address") or "")
                if peer.get("port"):
                    self.peer_port_spin.setValue(int(peer.get("port")))

        if not peer_host:
            self._reject_send("Choose or enter a peer host before sending.")
            return

        vlan_id = self.vlan_spin.value() or None
        mode = self._resolve_transport_mode(peer_host, vlan_id)
        config = TransportConfig(
            mode=mode,
            port=self.peer_port_spin.value(),
            mtu=self.mtu_spin.value(),
            allow_unknown=self.allow_unknown_checkbox.isChecked(),
            vlan_id=vlan_id,
        )

        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.transfer_detail_label.setText("Sending...")
        self._start_pulse(self.transfer_detail_label)
        self.status_changed.emit(f"Sending {Path(file_path).name} in {mode.upper()} mode...")
        self._transfer_start = time.monotonic()

        on_progress = self._make_progress_emitter()

        def _worker() -> None:
            try:
                if mode == "wan":
                    stats = udp_send_file(
                        file_path, peer_host, config.port, config=config, progress=on_progress
                    )
                else:
                    stats = send_file(file_path, peer_host, config=config, progress=on_progress)
            except Exception as exc:
                self.transfer_failed.emit(str(exc))
                return
            self.transfer_finished.emit(file_path, stats.bytes_transferred, stats.chunks)

        threading.Thread(target=_worker, daemon=True).start()

    def _coordination_settings(self):
        """Return (rendezvous_addr, relay_addr, stun_kwargs) or None if not set up."""
        settings = Settings.load(self._settings_base_dir)
        try:
            rendezvous_addr = settings.rendezvous_addr()
            relay_addr = settings.relay_addr()
        except SettingsError as exc:
            return ("error", str(exc))
        if rendezvous_addr is None:
            return None
        stun_kwargs: dict[str, Any] = {}
        if settings.stun_host:
            stun_kwargs["stun_host"] = settings.stun_host
        if settings.stun_port:
            stun_kwargs["stun_port"] = settings.stun_port
        return rendezvous_addr, relay_addr, stun_kwargs

    def _make_progress_emitter(self):
        last_emit = [0.0]

        def on_progress(sent: int, total: int) -> None:
            now = time.monotonic()
            if sent >= total or now - last_emit[0] >= 0.05:
                last_emit[0] = now
                self.transfer_progress.emit(sent, total)

        return on_progress

    def _send_over_internet(self, file_path: str, token: str) -> None:
        resolved = self._coordination_settings()
        if resolved is None:
            self._reject_send(
                "To send over the internet, set a Rendezvous server in the Settings tab "
                "(or clear the Internet token to send directly)."
            )
            return
        if resolved[0] == "error":
            self._reject_send(f"Invalid coordination server in Settings: {resolved[1]}")
            return
        rendezvous_addr, relay_addr, stun_kwargs = resolved

        config = TransportConfig(mode="wan", allow_unknown=self.allow_unknown_checkbox.isChecked())
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.transfer_detail_label.setText("Connecting via coordination server...")
        self._start_pulse(self.transfer_detail_label)
        self.status_changed.emit(f"Sending {Path(file_path).name} over the internet...")
        self._transfer_start = time.monotonic()
        on_progress = self._make_progress_emitter()

        def _worker() -> None:
            try:
                stats = wan_send_file(
                    file_path,
                    rendezvous_addr=rendezvous_addr,
                    token=token,
                    relay_addr=relay_addr,
                    config=config,
                    progress=on_progress,
                    base_dir=self._settings_base_dir,
                    **stun_kwargs,
                )
            except Exception as exc:
                self.transfer_failed.emit(str(exc))
                return
            self.transfer_finished.emit(file_path, stats.bytes_transferred, stats.chunks)

        threading.Thread(target=_worker, daemon=True).start()

    def _on_transfer_progress(self, sent: int, total: int) -> None:
        percent = int(sent * 100 / total) if total else 0
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(percent)
        elapsed = time.monotonic() - getattr(self, "_transfer_start", time.monotonic())
        rate = sent / elapsed if elapsed > 0 else 0.0
        self.transfer_detail_label.setText(
            f"{_human_bytes(sent)} / {_human_bytes(total)}  ·  {_human_bytes(rate)}/s"
        )

    def _resolve_transport_mode(self, peer_host: str, vlan_id: int | None) -> str:
        choice = self.mode_combo.currentText().strip().lower()
        if choice in {"lan", "vlan", "wan", "vpn"}:
            return choice
        return auto_select_transport_mode(vlan_id=vlan_id, peer_address=peer_host)

    def _on_transfer_finished(self, file_path: str, bytes_sent: int, chunks: int) -> None:
        self._stop_pulse(self.transfer_detail_label)
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(100)
        self.transfer_detail_label.setText(
            f"Sent {_human_bytes(bytes_sent)} across {chunks} chunk(s)"
        )
        self.status_changed.emit(f"Sent {Path(file_path).name} successfully")
        self.refresh_logs()

    def _on_transfer_failed(self, message: str) -> None:
        self._stop_pulse(self.transfer_detail_label)
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.transfer_detail_label.setText("Transfer failed")
        QMessageBox.critical(self, "SecureLink", message)
        self.status_changed.emit("Transfer failed")

    def _set_status(self, message: str) -> None:
        self.status_label.setText(message)
        self.statusBar().showMessage(message)

    def _resize_table_columns(self, table: QTableWidget, *, stretch_last: bool = False) -> None:
        header = table.horizontalHeader()
        column_count = table.columnCount()
        if column_count == 0:
            return
        for column in range(column_count - 1):
            header.setSectionResizeMode(column, QHeaderView.ResizeToContents)
        if stretch_last:
            header.setSectionResizeMode(column_count - 1, QHeaderView.Stretch)
        else:
            header.setSectionResizeMode(column_count - 1, QHeaderView.ResizeToContents)

    def closeEvent(self, event) -> None:  # type: ignore[override]
        if hasattr(self, "_log_timer"):
            self._log_timer.stop()
        if self._receive_cancel is not None:
            self._receive_cancel.set()
        super().closeEvent(event)


DashboardApp = DashboardWindow


def _install_exception_guard() -> None:
    """Keep the GUI alive when a slot raises.

    PyQt aborts the whole process on an uncaught exception in a slot — under
    ``pythonw`` that looks like a silent crash. Logging instead of aborting turns
    an edge-case bug into a survivable, diagnosable error.
    """

    def report(exc_type: type, exc: BaseException, tb: Any) -> None:
        message = "".join(traceback.format_exception(exc_type, exc, tb))
        sys.stderr.write(message)
        try:
            log_path = Path.home() / ".securelink" / "logs" / "ui-errors.log"
            log_path.parent.mkdir(parents=True, exist_ok=True)
            with log_path.open("a", encoding="utf-8") as handle:
                handle.write(f"{date.today().isoformat()} {message}\n")
        except OSError:
            pass

    sys.excepthook = report
    if hasattr(threading, "excepthook"):
        threading.excepthook = lambda args: report(
            args.exc_type, args.exc_value, args.exc_traceback
        )


def launch_dashboard() -> int:
    _claim_taskbar_identity()
    _install_exception_guard()

    app = QApplication.instance()
    owns_app = app is None
    if app is None:
        app = QApplication([])

    assert app is not None
    app.setApplicationName("SecureLink")
    app.setApplicationDisplayName("SecureLink Dashboard")
    if ICON_PATH.exists():
        app.setWindowIcon(QIcon(str(ICON_PATH)))
    app.setStyle("Fusion")

    window = DashboardWindow()
    window.show()

    if owns_app:
        return int(app.exec_())
    return 0


if __name__ == "__main__":
    raise SystemExit(launch_dashboard())
