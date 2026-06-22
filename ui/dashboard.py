from __future__ import annotations

import ipaddress
import json
import threading
import time
from datetime import date
from pathlib import Path
from typing import Any

from PyQt5.QtCore import Qt, QTimer, pyqtSignal
from PyQt5.QtGui import QColor, QFont
from PyQt5.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFrame,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QSpinBox,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from core.discovery import discover_peers
from core.transport import TransportConfig, receive_file, send_file
from core.udp_transport import udp_receive_file, udp_send_file

LOG_DIR = Path.home() / ".securelink" / "logs"


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
        self._receive_thread: threading.Thread | None = None
        self._receive_cancel: threading.Event | None = None
        self._build_window()
        self._connect_signals()
        self._configure_refresh()
        if self._auto_refresh:
            self.refresh_peers()
        self.refresh_logs()

    def _build_window(self) -> None:
        self.setWindowTitle("SecureLink Dashboard")
        self.resize(1480, 920)
        self.setMinimumSize(1240, 780)
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
            "Cross-network file transfer dashboard with LAN and VLAN awareness"
        )
        subtitle.setObjectName("HeaderSubtitle")

        self.status_label = QLabel("Ready")
        self.status_label.setObjectName("StatusLabel")

        header_layout.addWidget(title)
        header_layout.addWidget(subtitle)
        header_layout.addWidget(self.status_label)

        splitter = QSplitter(Qt.Horizontal, central_widget)
        splitter.setChildrenCollapsible(False)

        left_panel = QWidget(splitter)
        left_layout = QVBoxLayout(left_panel)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(12)

        right_panel = QWidget(splitter)
        right_layout = QVBoxLayout(right_panel)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(12)

        self._build_transfer_panel(left_layout)
        self._build_receive_panel(left_layout)
        self._build_network_panel(left_layout)
        self._build_log_panel(right_layout)
        self._build_alert_panel(right_layout)

        splitter.addWidget(left_panel)
        splitter.addWidget(right_panel)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 2)

        root_layout.addWidget(header)
        root_layout.addWidget(splitter)

        self.statusBar().showMessage("Ready")

    def _apply_styles(self) -> None:
        self.setStyleSheet(
            """
            QMainWindow {
                background: #f4f7fb;
            }
            QFrame#HeaderCard {
                background: #ffffff;
                border: 1px solid #d7e0ea;
                border-radius: 14px;
            }
            QLabel#HeaderTitle {
                color: #1f2937;
            }
            QLabel#HeaderSubtitle {
                color: #5b6470;
            }
            QLabel#StatusLabel {
                color: #2563eb;
                font-weight: 600;
            }
            QGroupBox {
                background: #ffffff;
                border: 1px solid #d7e0ea;
                border-radius: 12px;
                margin-top: 14px;
                padding: 10px;
                font-weight: 600;
                color: #1f2937;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 12px;
                padding: 0 6px;
            }
            QLineEdit, QComboBox, QSpinBox, QTableWidget {
                background: #ffffff;
                border: 1px solid #cbd5e1;
                border-radius: 8px;
                padding: 6px 8px;
            }
            QLineEdit:focus, QComboBox:focus, QSpinBox:focus {
                border: 1px solid #2563eb;
            }
            QPushButton {
                background: #2563eb;
                color: #ffffff;
                border: none;
                border-radius: 8px;
                padding: 8px 14px;
                font-weight: 600;
            }
            QPushButton:hover {
                background: #1d4ed8;
            }
            QPushButton:disabled {
                background: #93c5fd;
            }
            QTableWidget {
                alternate-background-color: #f8fafc;
                gridline-color: #e2e8f0;
            }
            QHeaderView::section {
                background: #edf2ff;
                color: #1f2937;
                padding: 6px 8px;
                border: none;
                border-bottom: 1px solid #d7e0ea;
                font-weight: 600;
            }
            QProgressBar {
                border: 1px solid #cbd5e1;
                border-radius: 8px;
                background: #ffffff;
                text-align: center;
                height: 18px;
            }
            QProgressBar::chunk {
                border-radius: 8px;
                background: #2563eb;
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
        self.logs_loaded.connect(self._render_logs)
        self.status_changed.connect(self._set_status)
        self.transfer_finished.connect(self._on_transfer_finished)
        self.transfer_failed.connect(self._on_transfer_failed)
        self.transfer_progress.connect(self._on_transfer_progress)
        self.receive_finished.connect(self._on_receive_finished)
        self.receive_failed.connect(self._on_receive_failed)

    def _build_transfer_panel(self, parent_layout: QVBoxLayout) -> None:
        group = QGroupBox("Transfer Panel")
        grid = QGridLayout(group)
        grid.setHorizontalSpacing(10)
        grid.setVerticalSpacing(10)
        grid.setColumnStretch(1, 1)
        grid.setColumnStretch(3, 1)

        self.file_edit = QLineEdit()
        self.file_edit.setPlaceholderText("Choose a file to send")
        browse_button = QPushButton("Browse")
        browse_button.clicked.connect(self.choose_file)

        self.peer_selector = QComboBox()
        self.peer_selector.currentIndexChanged.connect(self._apply_selected_peer)
        self.peer_selector.setPlaceholderText("Discover peers")

        self.peer_host_edit = QLineEdit()
        self.peer_host_edit.setPlaceholderText("Peer host or IP")

        self.peer_port_spin = QSpinBox()
        self.peer_port_spin.setRange(1, 65535)
        self.peer_port_spin.setValue(55000)

        self.mode_combo = QComboBox()
        self.mode_combo.addItems(["Auto", "LAN", "VLAN", "WAN"])

        self.mtu_spin = QSpinBox()
        self.mtu_spin.setRange(576, 9000)
        self.mtu_spin.setValue(1500)

        self.vlan_spin = QSpinBox()
        self.vlan_spin.setRange(0, 4094)
        self.vlan_spin.setValue(0)
        self.vlan_spin.setSpecialValueText("None")

        self.allow_unknown_checkbox = QCheckBox("Allow unknown devices")

        self.refresh_peers_button = QPushButton("Refresh Peers")
        self.refresh_peers_button.clicked.connect(self.refresh_peers)

        self.send_button = QPushButton("Send File")
        self.send_button.clicked.connect(self.send_selected_file)

        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.transfer_detail_label = QLabel("Idle")
        self.transfer_detail_label.setObjectName("TransferDetails")

        grid.addWidget(QLabel("File"), 0, 0)
        grid.addWidget(self.file_edit, 0, 1, 1, 2)
        grid.addWidget(browse_button, 0, 3)

        grid.addWidget(QLabel("Discovered peer"), 1, 0)
        grid.addWidget(self.peer_selector, 1, 1, 1, 3)

        grid.addWidget(QLabel("Peer host"), 2, 0)
        grid.addWidget(self.peer_host_edit, 2, 1)
        grid.addWidget(QLabel("Port"), 2, 2)
        grid.addWidget(self.peer_port_spin, 2, 3)

        grid.addWidget(QLabel("Mode"), 3, 0)
        grid.addWidget(self.mode_combo, 3, 1)
        grid.addWidget(QLabel("MTU"), 3, 2)
        grid.addWidget(self.mtu_spin, 3, 3)

        grid.addWidget(QLabel("VLAN ID"), 4, 0)
        grid.addWidget(self.vlan_spin, 4, 1)
        grid.addWidget(self.allow_unknown_checkbox, 4, 2, 1, 2)

        button_row = QHBoxLayout()
        button_row.addWidget(self.refresh_peers_button)
        button_row.addStretch(1)
        button_row.addWidget(self.send_button)
        grid.addLayout(button_row, 5, 0, 1, 4)

        grid.addWidget(self.progress_bar, 6, 0, 1, 3)
        grid.addWidget(self.transfer_detail_label, 6, 3)

        parent_layout.addWidget(group)

    def _build_receive_panel(self, parent_layout: QVBoxLayout) -> None:
        group = QGroupBox("Receive Panel")
        grid = QGridLayout(group)
        grid.setHorizontalSpacing(10)
        grid.setVerticalSpacing(10)
        grid.setColumnStretch(1, 1)

        self.recv_port_spin = QSpinBox()
        self.recv_port_spin.setRange(1, 65535)
        self.recv_port_spin.setValue(55000)

        self.recv_wan_checkbox = QCheckBox("WAN (reliable UDP)")

        self.recv_output_edit = QLineEdit(str(Path.cwd()))
        recv_browse_button = QPushButton("Browse")
        recv_browse_button.clicked.connect(self.choose_output_dir)

        self.recv_allowlist_edit = QLineEdit()
        self.recv_allowlist_edit.setPlaceholderText("Allowlist, e.g. 192.168.1.0/24, 10.0.0.5")

        self.recv_allow_unknown_checkbox = QCheckBox("Allow unknown devices")

        self.receive_button = QPushButton("Start Listening")
        self.receive_button.clicked.connect(self.toggle_receiving)

        self.receive_status_label = QLabel("Idle")
        self.receive_status_label.setObjectName("ReceiveStatus")

        grid.addWidget(QLabel("Port"), 0, 0)
        grid.addWidget(self.recv_port_spin, 0, 1)
        grid.addWidget(self.recv_wan_checkbox, 0, 2, 1, 2)

        grid.addWidget(QLabel("Save to"), 1, 0)
        grid.addWidget(self.recv_output_edit, 1, 1, 1, 2)
        grid.addWidget(recv_browse_button, 1, 3)

        grid.addWidget(QLabel("Allowlist"), 2, 0)
        grid.addWidget(self.recv_allowlist_edit, 2, 1)
        grid.addWidget(self.recv_allow_unknown_checkbox, 2, 2, 1, 2)

        button_row = QHBoxLayout()
        button_row.addWidget(self.receive_button)
        button_row.addWidget(self.receive_status_label, 1)
        grid.addLayout(button_row, 3, 0, 1, 4)

        parent_layout.addWidget(group)

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

    def _reset_receive_button(self) -> None:
        self.receive_button.setText("Start Listening")
        self.receive_button.setEnabled(True)

    def _on_receive_finished(self, path: str, bytes_received: int, chunks: int) -> None:
        self._reset_receive_button()
        name = Path(path).name
        self.receive_status_label.setText(
            f"Received {name} ({bytes_received} bytes, {chunks} chunk(s))"
        )
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
        group = QGroupBox("Network Map")
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

        layout.addWidget(self.network_table)
        parent_layout.addWidget(group, stretch=1)

    def _build_log_panel(self, parent_layout: QVBoxLayout) -> None:
        group = QGroupBox("Live Log Panel")
        layout = QVBoxLayout(group)
        layout.setContentsMargins(10, 10, 10, 10)

        header_row = QHBoxLayout()
        self.log_refresh_button = QPushButton("Refresh Logs")
        self.log_refresh_button.clicked.connect(self.refresh_logs)
        self.log_summary_label = QLabel("0 events, 0 alerts")
        self.log_summary_label.setObjectName("LogSummary")
        header_row.addWidget(self.log_refresh_button)
        header_row.addStretch(1)
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
        group = QGroupBox("Alert Panel")
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

        def _worker() -> None:
            try:
                discovered = discover_peers()
                peer_records = [dict(vars(peer)) for peer in discovered]
            except Exception as exc:
                self.status_changed.emit(f"Peer discovery unavailable: {exc}")
                return
            self.peers_loaded.emit(peer_records)

        threading.Thread(target=_worker, daemon=True).start()

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
        entries = list(payload) if isinstance(payload, list) else []
        alert_entries = list(alerts) if isinstance(alerts, list) else []

        self.log_summary_label.setText(f"{len(entries)} events, {len(alert_entries)} alerts")
        self.alert_summary_label.setText(f"{len(alert_entries)} active alerts")

        self.log_table.setRowCount(len(entries))
        for row, entry in enumerate(entries):
            if not isinstance(entry, dict):
                continue
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
                    item.setBackground(QColor("#fee2e2"))
                    item.setForeground(QColor("#7f1d1d"))
                self.log_table.setItem(row, column, item)

        self.alert_table.setRowCount(len(alert_entries))
        for row, entry in enumerate(alert_entries):
            if not isinstance(entry, dict):
                continue
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
                    item.setBackground(QColor("#fee2e2"))
                    item.setForeground(QColor("#7f1d1d"))
                elif severity == "MEDIUM":
                    item.setBackground(QColor("#fef3c7"))
                    item.setForeground(QColor("#92400e"))
                self.alert_table.setItem(row, column, item)

        self._resize_table_columns(self.log_table, stretch_last=True)
        self._resize_table_columns(self.alert_table, stretch_last=True)

    def send_selected_file(self) -> None:
        file_path = self.file_edit.text().strip()
        if not file_path:
            QMessageBox.warning(self, "SecureLink", "Choose a file before sending.")
            return

        peer_host = self.peer_host_edit.text().strip()
        if not peer_host and self.peer_selector.currentIndex() >= 0:
            peer = self.peer_selector.currentData()
            if isinstance(peer, dict):
                peer_host = str(peer.get("address") or "")
                if peer.get("port"):
                    self.peer_port_spin.setValue(int(peer.get("port")))

        if not peer_host:
            QMessageBox.warning(self, "SecureLink", "Choose or enter a peer host before sending.")
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
        self.status_changed.emit(f"Sending {Path(file_path).name} in {mode.upper()} mode...")
        self._transfer_start = time.monotonic()

        last_emit = [0.0]

        def on_progress(sent: int, total: int) -> None:
            now = time.monotonic()
            if sent >= total or now - last_emit[0] >= 0.05:
                last_emit[0] = now
                self.transfer_progress.emit(sent, total)

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
        if choice in {"lan", "vlan", "wan"}:
            return choice
        if vlan_id is not None:
            return "vlan"
        try:
            peer_ip = ipaddress.ip_address(peer_host)
        except ValueError:
            return "lan"
        if peer_ip.is_private or peer_ip.is_loopback or peer_ip.is_link_local:
            return "lan"
        return "wan"

    def _on_transfer_finished(self, file_path: str, bytes_sent: int, chunks: int) -> None:
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(100)
        self.transfer_detail_label.setText(
            f"Sent {_human_bytes(bytes_sent)} across {chunks} chunk(s)"
        )
        self.status_changed.emit(f"Sent {Path(file_path).name} successfully")
        self.refresh_logs()

    def _on_transfer_failed(self, message: str) -> None:
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


def launch_dashboard() -> int:
    app = QApplication.instance()
    owns_app = app is None
    if app is None:
        app = QApplication([])

    assert app is not None
    app.setStyle("Fusion")

    window = DashboardWindow()
    window.show()

    if owns_app:
        return int(app.exec_())
    return 0


if __name__ == "__main__":
    raise SystemExit(launch_dashboard())
