#!/usr/bin/env python3
import configparser
import ipaddress
import json
import os
import queue
import subprocess
import sys
import threading
from pathlib import Path

from PySide6.QtCore import QTimer, Qt
from PySide6.QtGui import QAction, QCloseEvent, QIcon, QPixmap, QPainter, QColor
from PySide6.QtWidgets import (
    QApplication,
    QComboBox,
    QCheckBox,
    QFormLayout,
    QGridLayout,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMenu,
    QMessageBox,
    QPushButton,
    QSplitter,
    QSystemTrayIcon,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from camera_linux_tool import (
    discover_onvif_streams,
    discover_rtsp_candidates,
    nmap_discover_hosts,
    open_with_ffplay,
    ptz_get_presets,
    ptz_get_status,
    ptz_goto_preset,
    ptz_relative_move,
    ptz_remove_preset,
    ptz_set_preset,
)


APP_NAME = "camera-discovery"
CONFIG_SECTION = "settings"
DEFAULT_TARGETS = "192.168.1.0/24"
AUTOSTART_FILENAME = "camera-discovery.desktop"
AUTHOR_NAME = "Henrique Fernandes Silveira"
AUTHOR_EMAIL = "henriquefsilveira@gmail.com"


def config_path() -> Path:
    base = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
    folder = base / APP_NAME
    folder.mkdir(parents=True, exist_ok=True)
    return folder / "settings.conf"


def cache_path() -> Path:
    return config_path().with_name("last_results.json")


def autostart_path() -> Path:
    base = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
    folder = base / "autostart"
    folder.mkdir(parents=True, exist_ok=True)
    return folder / AUTOSTART_FILENAME


def split_targets(value: str) -> list[str]:
    raw = value.replace("\n", ",").replace(" ", ",")
    return [item.strip() for item in raw.split(",") if item.strip()]


def expand_targets(value: str) -> list[str]:
    expanded = []
    seen = set()

    for item in split_targets(value):
        if "/" in item:
            network = ipaddress.ip_network(item, strict=False)
            for host in network.hosts():
                ip = str(host)
                if ip not in seen:
                    seen.add(ip)
                    expanded.append(ip)
            continue

        ip = str(ipaddress.ip_address(item))
        if ip not in seen:
            seen.add(ip)
            expanded.append(ip)

    return expanded


def guess_best_url(result: dict) -> str | None:
    streams = result.get("streams", [])
    if streams:
        return streams[0]["url"]

    candidates = result.get("rtsp_candidates", [])
    for preferred in ("/onvif1", "/onvif2"):
        for candidate in candidates:
            if candidate.get("path") == preferred:
                return candidate["url"]

    if candidates:
        return candidates[0]["url"]

    return None


class CameraDiscoveryWindow(QMainWindow):
    def __init__(self, start_minimized: bool = False):
        super().__init__()
        self.setWindowTitle("Camera Discovery")
        self.resize(1180, 760)

        self.results: dict[str, dict] = {}
        self.preserved_results: dict[str, dict] = {}
        self.result_queue: queue.Queue = queue.Queue()
        self.scan_thread: threading.Thread | None = None
        self.stop_event = threading.Event()
        self.tray_icon: QSystemTrayIcon | None = None
        self.tray_available = QSystemTrayIcon.isSystemTrayAvailable()
        self.player_processes: list[subprocess.Popen] = []
        self.start_minimized = start_minimized

        self.targets_edit = QLineEdit(DEFAULT_TARGETS)
        self.user_edit = QLineEdit("admin")
        self.password_edit = QLineEdit()
        self.password_edit.setEchoMode(QLineEdit.Password)
        self.timeout_edit = QLineEdit("4.0")
        self.rtsp_delay_edit = QLineEdit("2.0")
        self.rtsp_max_edit = QLineEdit("1")
        self.transport_combo = QComboBox()
        self.transport_combo.addItems(["auto", "tcp", "udp"])
        self.max_delay_edit = QLineEdit("0")
        self.disable_audio_check = QCheckBox("Abrir sem audio")
        self.skip_rtsp_when_onvif_check = QCheckBox("Se ONVIF achar stream, nao testar RTSP direto")
        self.skip_rtsp_when_onvif_check.setChecked(True)
        self.use_nmap_prescan_check = QCheckBox("Usar nmap para pre-scan de redes")
        self.use_nmap_prescan_check.setChecked(True)
        self.minimize_to_tray_check = QCheckBox("Minimizar para tray ao fechar")
        self.minimize_to_tray_check.setChecked(True)
        self.autostart_check = QCheckBox("Iniciar com a sessao no tray")
        self.saved_name_edit = QLineEdit()
        self.url_edit = QLineEdit()
        self.status_label = QLabel("Pronto.")
        self.tray_menu: QMenu | None = None
        self.saved_cameras_menu: QMenu | None = None
        self.ptz_status_label = QLabel("PTZ: indisponivel.")
        self.ptz_profile_label = QLabel("Profile PTZ: -")
        self.ptz_presets_info_label = QLabel("Presets PTZ: -")
        self.ptz_debug_label = QLabel("Debug PTZ: -")
        self.ptz_profile_combo = QComboBox()
        self.ptz_preset_name_edit = QLineEdit()
        self.ptz_preset_list = QListWidget()

        self.camera_table = QTableWidget(0, 3)
        self.url_list = QListWidget()
        self.detail_text = QTextEdit()
        self.detail_text.setReadOnly(True)

        self._build_ui()
        self._load_config()
        self._load_cached_results()
        self._setup_tray()

        self.queue_timer = QTimer(self)
        self.queue_timer.timeout.connect(self._process_queue)
        self.queue_timer.start(150)

    def _build_ui(self) -> None:
        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)

        form = QFormLayout()
        form.addRow("IPs ou redes", self.targets_edit)

        cred_row = QHBoxLayout()
        cred_row.addWidget(QLabel("Usuario"))
        cred_row.addWidget(self.user_edit)
        cred_row.addWidget(QLabel("Senha"))
        cred_row.addWidget(self.password_edit)
        cred_row.addWidget(QLabel("Timeout"))
        cred_row.addWidget(self.timeout_edit)
        form.addRow(cred_row)

        rtsp_row = QHBoxLayout()
        rtsp_row.addWidget(QLabel("Atraso RTSP"))
        rtsp_row.addWidget(self.rtsp_delay_edit)
        rtsp_row.addWidget(QLabel("Max RTSP"))
        rtsp_row.addWidget(self.rtsp_max_edit)
        rtsp_row.addWidget(QLabel("Transporte"))
        rtsp_row.addWidget(self.transport_combo)
        rtsp_row.addWidget(QLabel("max_delay(us)"))
        rtsp_row.addWidget(self.max_delay_edit)
        rtsp_row.addWidget(self.disable_audio_check)
        form.addRow(rtsp_row)

        root.addLayout(form)
        root.addWidget(self.skip_rtsp_when_onvif_check)
        root.addWidget(self.use_nmap_prescan_check)
        root.addWidget(self.minimize_to_tray_check)
        root.addWidget(self.autostart_check)
        root.addWidget(QLabel("Tray disponivel" if self.tray_available else "Tray indisponivel neste ambiente"))

        actions = QHBoxLayout()
        scan_button = QPushButton("Escanear")
        stop_button = QPushButton("Parar")
        clear_button = QPushButton("Limpar")
        minimize_button = QPushButton("Minimizar")
        about_button = QPushButton("Sobre")
        scan_button.clicked.connect(self.start_scan)
        stop_button.clicked.connect(self.stop_scan)
        clear_button.clicked.connect(self.clear_results)
        minimize_button.clicked.connect(self.minimize_to_tray)
        about_button.clicked.connect(self.show_about)
        actions.addWidget(scan_button)
        actions.addWidget(stop_button)
        actions.addWidget(clear_button)
        actions.addWidget(minimize_button)
        actions.addWidget(about_button)
        actions.addWidget(self.status_label, 1)
        root.addLayout(actions)

        splitter = QSplitter(Qt.Horizontal)
        root.addWidget(splitter, 1)

        left = QWidget()
        left_layout = QVBoxLayout(left)
        left_layout.addWidget(QLabel("Cameras"))
        self.camera_table.setHorizontalHeaderLabels(["IP", "Deteccao", "Melhor URL"])
        self.camera_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.camera_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.camera_table.setAlternatingRowColors(True)
        self.camera_table.horizontalHeader().setStretchLastSection(True)
        self.camera_table.itemSelectionChanged.connect(self.on_camera_select)
        left_layout.addWidget(self.camera_table)
        splitter.addWidget(left)

        right = QWidget()
        right_layout = QVBoxLayout(right)
        right_layout.addWidget(QLabel("URLs encontradas"))
        self.url_list.itemSelectionChanged.connect(self.on_url_select)
        right_layout.addWidget(self.url_list)
        right_layout.addWidget(QLabel("Nome salvo da camera"))
        right_layout.addWidget(self.saved_name_edit)
        self.saved_name_edit.editingFinished.connect(self._persist_current_saved_name)
        right_layout.addWidget(QLabel("URL para abrir"))
        right_layout.addWidget(self.url_edit)
        self.url_edit.editingFinished.connect(self._persist_current_url)

        url_actions = QHBoxLayout()
        save_camera_button = QPushButton("Salvar camera")
        best_button = QPushButton("Usar melhor URL")
        open_button = QPushButton("Abrir no ffplay")
        copy_button = QPushButton("Copiar")
        save_camera_button.clicked.connect(self.save_current_camera)
        best_button.clicked.connect(self.use_best_url)
        open_button.clicked.connect(self.open_selected_url)
        copy_button.clicked.connect(self.copy_url)
        url_actions.addWidget(save_camera_button)
        url_actions.addWidget(best_button)
        url_actions.addWidget(open_button)
        url_actions.addWidget(copy_button)
        right_layout.addLayout(url_actions)

        ptz_layout = QVBoxLayout()
        ptz_layout.addWidget(QLabel("PTZ"))
        ptz_layout.addWidget(self.ptz_status_label)
        ptz_layout.addWidget(self.ptz_profile_label)
        ptz_layout.addWidget(self.ptz_presets_info_label)
        ptz_layout.addWidget(self.ptz_debug_label)
        self.ptz_profile_combo.currentTextChanged.connect(self.on_ptz_profile_changed)
        ptz_layout.addWidget(self.ptz_profile_combo)
        ptz_grid = QGridLayout()
        ptz_up_left = QPushButton("Cima Esq")
        ptz_up = QPushButton("Cima")
        ptz_up_right = QPushButton("Cima Dir")
        ptz_left = QPushButton("Esquerda")
        ptz_right = QPushButton("Direita")
        ptz_down_left = QPushButton("Baixo Esq")
        ptz_down = QPushButton("Baixo")
        ptz_down_right = QPushButton("Baixo Dir")
        zoom_in_button = QPushButton("Zoom +")
        zoom_out_button = QPushButton("Zoom -")
        refresh_ptz_button = QPushButton("Atualizar PTZ")

        ptz_up_left.clicked.connect(lambda: self._move_selected_camera_ptz(-0.1, -0.1))
        ptz_up.clicked.connect(lambda: self._move_selected_camera_ptz(0.0, -0.1))
        ptz_up_right.clicked.connect(lambda: self._move_selected_camera_ptz(0.1, -0.1))
        ptz_left.clicked.connect(lambda: self._move_selected_camera_ptz(-0.1, 0.0))
        ptz_right.clicked.connect(lambda: self._move_selected_camera_ptz(0.1, 0.0))
        ptz_down_left.clicked.connect(lambda: self._move_selected_camera_ptz(-0.1, 0.1))
        ptz_down.clicked.connect(lambda: self._move_selected_camera_ptz(0.0, 0.1))
        ptz_down_right.clicked.connect(lambda: self._move_selected_camera_ptz(0.1, 0.1))
        zoom_in_button.clicked.connect(lambda: self._move_selected_camera_ptz(0.0, 0.0, 0.1))
        zoom_out_button.clicked.connect(lambda: self._move_selected_camera_ptz(0.0, 0.0, -0.1))
        refresh_ptz_button.clicked.connect(self.refresh_selected_ptz_status)

        ptz_grid.addWidget(ptz_up_left, 0, 0)
        ptz_grid.addWidget(ptz_up, 0, 1)
        ptz_grid.addWidget(ptz_up_right, 0, 2)
        ptz_grid.addWidget(ptz_left, 1, 0)
        ptz_grid.addWidget(refresh_ptz_button, 1, 1)
        ptz_grid.addWidget(ptz_right, 1, 2)
        ptz_grid.addWidget(ptz_down_left, 2, 0)
        ptz_grid.addWidget(ptz_down, 2, 1)
        ptz_grid.addWidget(ptz_down_right, 2, 2)
        ptz_grid.addWidget(zoom_in_button, 0, 3)
        ptz_grid.addWidget(zoom_out_button, 1, 3)
        ptz_layout.addLayout(ptz_grid)

        preset_row = QHBoxLayout()
        preset_row.addWidget(QLabel("Nome do preset"))
        preset_row.addWidget(self.ptz_preset_name_edit)
        save_preset_button = QPushButton("Salvar posicao")
        goto_preset_button = QPushButton("Ir para preset")
        delete_preset_button = QPushButton("Excluir preset")
        refresh_preset_button = QPushButton("Atualizar presets")
        save_preset_button.clicked.connect(self.save_selected_ptz_preset)
        goto_preset_button.clicked.connect(self.goto_selected_ptz_preset)
        delete_preset_button.clicked.connect(self.delete_selected_ptz_preset)
        refresh_preset_button.clicked.connect(self.refresh_selected_ptz_presets)
        preset_row.addWidget(save_preset_button)
        preset_row.addWidget(goto_preset_button)
        preset_row.addWidget(delete_preset_button)
        preset_row.addWidget(refresh_preset_button)
        ptz_layout.addLayout(preset_row)
        self.ptz_preset_list.itemDoubleClicked.connect(lambda _item: self.goto_selected_ptz_preset())
        ptz_layout.addWidget(self.ptz_preset_list)
        right_layout.addLayout(ptz_layout)
        right_layout.addWidget(self.detail_text, 1)
        splitter.addWidget(right)
        splitter.setSizes([420, 740])

    def _build_icon(self) -> QIcon:
        pixmap = QPixmap(64, 64)
        pixmap.fill(QColor(24, 32, 42))
        painter = QPainter(pixmap)
        painter.setPen(QColor(90, 220, 180))
        painter.drawRect(10, 16, 44, 30)
        painter.drawEllipse(24, 24, 16, 16)
        painter.fillRect(18, 46, 28, 8, QColor(90, 220, 180))
        painter.end()
        return QIcon(pixmap)

    def _setup_tray(self) -> None:
        if not self.tray_available:
            return

        self.setWindowIcon(self._build_icon())
        self.tray_icon = QSystemTrayIcon(self.windowIcon(), self)
        self.tray_icon.setToolTip("Camera Discovery")

        menu = QMenu(self)
        self.tray_menu = menu
        self.saved_cameras_menu = menu.addMenu("Cameras salvas")
        open_action = QAction("Abrir", self)
        about_action = QAction("Sobre", self)
        quit_action = QAction("Sair", self)
        open_action.triggered.connect(self.restore_from_tray)
        about_action.triggered.connect(self.show_about)
        quit_action.triggered.connect(self.shutdown)
        self._refresh_tray_menu()
        menu.addAction(open_action)
        menu.addAction(about_action)
        menu.addAction(quit_action)
        self.tray_icon.setContextMenu(menu)
        self.tray_icon.activated.connect(self._on_tray_activated)
        self.tray_icon.show()

    def _on_tray_activated(self, reason) -> None:
        if reason == QSystemTrayIcon.Trigger:
            self.restore_from_tray()

    def _load_config(self) -> None:
        path = config_path()
        if not path.exists():
            return

        parser = configparser.ConfigParser()
        parser.read(path)
        if CONFIG_SECTION not in parser:
            return

        data = parser[CONFIG_SECTION]
        self.targets_edit.setText(data.get("targets", DEFAULT_TARGETS))
        self.user_edit.setText(data.get("username", "admin"))
        self.password_edit.setText(data.get("password", ""))
        self.timeout_edit.setText(data.get("timeout", "4.0"))
        self.rtsp_delay_edit.setText(data.get("rtsp_delay", "2.0"))
        self.rtsp_max_edit.setText(data.get("rtsp_max", "1"))
        transport = data.get("transport", "auto")
        index = self.transport_combo.findText(transport)
        self.transport_combo.setCurrentIndex(index if index >= 0 else 0)
        self.max_delay_edit.setText(data.get("max_delay_us", "0"))
        self.disable_audio_check.setChecked(data.getboolean("disable_audio", False))
        self.skip_rtsp_when_onvif_check.setChecked(data.getboolean("skip_rtsp_when_onvif", True))
        self.use_nmap_prescan_check.setChecked(data.getboolean("use_nmap_prescan", True))
        self.minimize_to_tray_check.setChecked(data.getboolean("minimize_to_tray", True))
        self.autostart_check.setChecked(data.getboolean("autostart", autostart_path().exists()))
        self.url_edit.setText(data.get("last_url", ""))

    def _save_config(self) -> None:
        self._persist_current_saved_name(save_cache=False)
        self._persist_current_url(save_cache=False)
        parser = configparser.ConfigParser()
        parser[CONFIG_SECTION] = {
            "targets": self.targets_edit.text(),
            "username": self.user_edit.text(),
            "password": self.password_edit.text(),
            "timeout": self.timeout_edit.text(),
            "rtsp_delay": self.rtsp_delay_edit.text(),
            "rtsp_max": self.rtsp_max_edit.text(),
            "transport": self.transport_combo.currentText(),
            "max_delay_us": self.max_delay_edit.text(),
            "disable_audio": str(self.disable_audio_check.isChecked()),
            "last_url": self.url_edit.text().strip(),
            "skip_rtsp_when_onvif": str(self.skip_rtsp_when_onvif_check.isChecked()),
            "use_nmap_prescan": str(self.use_nmap_prescan_check.isChecked()),
            "minimize_to_tray": str(self.minimize_to_tray_check.isChecked()),
            "autostart": str(self.autostart_check.isChecked()),
        }
        with config_path().open("w", encoding="utf-8") as fh:
            parser.write(fh)
        self._sync_autostart()

    def _load_cached_results(self) -> None:
        path = cache_path()
        if not path.exists():
            return

        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return

        if not isinstance(data, list):
            return

        for result in data:
            if isinstance(result, dict) and "ip" in result:
                self._add_camera_result(result)

        if data:
            self.status_label.setText("Resultados anteriores carregados. Escaneie de novo quando quiser atualizar.")

    def _save_cached_results(self) -> None:
        serializable = [self.results[ip] for ip in sorted(self.results)]
        try:
            cache_path().write_text(json.dumps(serializable, ensure_ascii=True, indent=2), encoding="utf-8")
        except OSError:
            pass
        self._refresh_tray_menu()

    def _set_status(self, text: str) -> None:
        self.status_label.setText(text)
        if self.tray_icon is not None:
            self.tray_icon.setToolTip(f"Camera Discovery\n{text}")

    def clear_results(self, preserve_saved: bool = False) -> None:
        if not preserve_saved:
            self.preserved_results = {}
        self.results.clear()
        self.camera_table.setRowCount(0)
        self.url_list.clear()
        self.saved_name_edit.clear()
        self.url_edit.clear()
        self.ptz_preset_name_edit.clear()
        self.ptz_preset_list.clear()
        self.ptz_status_label.setText("PTZ: indisponivel.")
        self.detail_text.clear()
        self._save_cached_results()
        self._set_status("Resultados limpos.")

    def start_scan(self) -> None:
        if self.scan_thread and self.scan_thread.is_alive():
            QMessageBox.information(self, "Scan em andamento", "Espere a busca atual terminar.")
            return

        try:
            ips = expand_targets(self.targets_edit.text())
        except ValueError as exc:
            QMessageBox.critical(self, "IPs ou redes", f"Entrada invalida: {exc}")
            return

        if not ips:
            QMessageBox.critical(self, "IPs ou redes", "Informe pelo menos um IP ou rede.")
            return

        try:
            timeout = float(self.timeout_edit.text())
        except ValueError:
            QMessageBox.critical(self, "Timeout", "Timeout invalido.")
            return

        try:
            rtsp_delay = float(self.rtsp_delay_edit.text())
        except ValueError:
            QMessageBox.critical(self, "Atraso RTSP", "Atraso RTSP invalido.")
            return

        try:
            rtsp_max = int(self.rtsp_max_edit.text())
        except ValueError:
            QMessageBox.critical(self, "Max RTSP", "Max RTSP invalido.")
            return

        if len(ips) > 256:
            proceed = QMessageBox.question(
                self,
                "Rede grande",
                f"Isso vai consultar {len(ips)} hosts. Deseja continuar?",
            )
            if proceed != QMessageBox.Yes:
                return

        self.preserved_results = {
            ip: {
                key: value
                for key, value in result.items()
                if key in {"saved_name", "saved_url", "ptz_presets", "ptz_presets_by_profile", "ptz_status", "ptz_profile_token"}
            }
            for ip, result in self.results.items()
        }
        self.clear_results(preserve_saved=True)
        self._save_config()
        self._set_status(f"Buscando cameras em {len(ips)} host(s)...")
        self.stop_event.clear()

        args = {
            "ips": ips,
            "target_text": self.targets_edit.text(),
            "username": self.user_edit.text().strip() or "admin",
            "password": self.password_edit.text(),
            "timeout": timeout,
            "rtsp_delay": rtsp_delay,
            "rtsp_max": rtsp_max,
            "skip_rtsp_when_onvif": self.skip_rtsp_when_onvif_check.isChecked(),
            "use_nmap_prescan": self.use_nmap_prescan_check.isChecked(),
            "stop_event": self.stop_event,
        }
        self.scan_thread = threading.Thread(target=self._scan_worker, args=(args,), daemon=True)
        self.scan_thread.start()

    def stop_scan(self) -> None:
        if not self.scan_thread or not self.scan_thread.is_alive():
            self._set_status("Nenhum scan em andamento.")
            return
        self.stop_event.set()
        self._set_status("Parando scan...")

    def _scan_worker(self, args: dict) -> None:
        ips = args["ips"]

        if args["use_nmap_prescan"]:
            network_targets = [item for item in split_targets(args["target_text"]) if "/" in item]
            if len(network_targets) == 1 and len(split_targets(args["target_text"])) == 1:
                target = network_targets[0]
                self.result_queue.put(("status", f"Pre-scan com nmap em {target}..."))
                nmap_hosts = nmap_discover_hosts(target)
                if nmap_hosts:
                    ips = nmap_hosts
                    self.result_queue.put(("status", f"nmap encontrou {len(ips)} host(s) ativos."))

        for ip in ips:
            if args["stop_event"].is_set():
                self.stop_event.clear()
                self.result_queue.put(("done", "Scan interrompido pelo usuario."))
                return

            self.result_queue.put(("status", f"Consultando {ip}..."))
            try:
                onvif, streams = discover_onvif_streams(ip, args["username"], args["password"], args["timeout"])
                ptz_presets = []
                if onvif and isinstance(onvif.get("ptz"), dict) and onvif["ptz"].get("available"):
                    ptz_presets = ptz_get_presets(
                        onvif["ptz"]["service_url"],
                        args["username"],
                        args["password"],
                        onvif["ptz"]["profile_token"],
                        args["timeout"],
                    )
                rtsp_candidates = []
                if not args["stop_event"].is_set() and not (args["skip_rtsp_when_onvif"] and streams):
                    rtsp_candidates = discover_rtsp_candidates(
                        ip,
                        args["username"],
                        args["password"],
                        args["timeout"],
                        delay=args["rtsp_delay"],
                        max_candidates=args["rtsp_max"],
                        stop_event=args["stop_event"],
                    )
                result = {
                    "ip": ip,
                    "onvif": onvif,
                    "streams": streams,
                    "ptz_presets_by_profile": {onvif["ptz"]["profile_token"]: ptz_presets} if ptz_presets and onvif and onvif.get("ptz") else {},
                    "ptz_presets": ptz_presets,
                    "rtsp_candidates": rtsp_candidates,
                }
            except Exception as exc:
                result = {
                    "ip": ip,
                    "onvif": None,
                    "streams": [],
                    "rtsp_candidates": [],
                    "error": str(exc),
                }
            self.result_queue.put(("camera", result))

        self.stop_event.clear()
        self.result_queue.put(("done", f"Busca finalizada. {len(ips)} host(s) processados."))

    def _process_queue(self) -> None:
        while True:
            try:
                kind, payload = self.result_queue.get_nowait()
            except queue.Empty:
                break

            if kind == "status":
                self._set_status(payload)
            elif kind == "camera":
                self._add_camera_result(payload)
            elif kind == "done":
                self._set_status(payload)

    def _add_camera_result(self, result: dict) -> None:
        ip = result["ip"]
        previous = self.results.get(ip, {})
        preserved = self.preserved_results.get(ip, {})
        for key in ("saved_name", "saved_url", "ptz_presets", "ptz_presets_by_profile", "ptz_status", "ptz_profile_token"):
            if key in previous and key not in result:
                result[key] = previous[key]
            elif key in preserved and key not in result:
                result[key] = preserved[key]

        if "ptz_presets" in result:
            result["ptz_presets"] = [
                preset for preset in result.get("ptz_presets", [])
                if isinstance(preset, dict) and preset.get("token")
            ]
        if isinstance(result.get("ptz_presets_by_profile"), dict):
            cleaned = {}
            for profile, presets in result["ptz_presets_by_profile"].items():
                cleaned[profile] = [
                    preset for preset in presets
                    if isinstance(preset, dict) and preset.get("token")
                ]
            result["ptz_presets_by_profile"] = cleaned

        has_detection = bool(result.get("onvif") or result.get("streams") or result.get("rtsp_candidates"))
        has_error = bool(result.get("error"))

        if not has_detection and not has_error:
            self.results.pop(ip, None)
            self._save_cached_results()
            return

        self.results[ip] = result
        best_url = guess_best_url(result) or ""

        if result.get("streams"):
            kind = "ONVIF"
        elif result.get("onvif"):
            kind = "ONVIF sem stream"
        elif result.get("rtsp_candidates"):
            kind = "RTSP direto"
        elif result.get("error"):
            kind = "Erro"
        else:
            kind = "Nada encontrado"

        row = self._row_for_ip(ip)
        if row is None:
            row = self.camera_table.rowCount()
            self.camera_table.insertRow(row)

        for column, value in enumerate([ip, kind, best_url]):
            self.camera_table.setItem(row, column, QTableWidgetItem(value))

        self._save_cached_results()
        if ip == self._selected_ip():
            self.on_camera_select()

    def _row_for_ip(self, ip: str) -> int | None:
        for row in range(self.camera_table.rowCount()):
            item = self.camera_table.item(row, 0)
            if item and item.text() == ip:
                return row
        return None

    def _selected_ip(self) -> str | None:
        row = self.camera_table.currentRow()
        if row < 0:
            return None
        item = self.camera_table.item(row, 0)
        return item.text() if item else None

    def _persist_current_url(self, save_cache: bool = True) -> None:
        ip = self._selected_ip()
        if not ip:
            return

        result = self.results.get(ip)
        if not result:
            return

        url = self.url_edit.text().strip()
        if url:
            result["saved_url"] = url
        else:
            result.pop("saved_url", None)

        if save_cache:
            self._save_cached_results()

    def _persist_current_saved_name(self, save_cache: bool = True) -> None:
        ip = self._selected_ip()
        if not ip:
            return

        result = self.results.get(ip)
        if not result:
            return

        saved_name = self.saved_name_edit.text().strip()
        if saved_name:
            result["saved_name"] = saved_name
        else:
            result.pop("saved_name", None)

        if save_cache:
            self._save_cached_results()

    def _saved_cameras(self) -> list[dict]:
        cameras = []
        for ip in sorted(self.results):
            result = self.results[ip]
            saved_name = (result.get("saved_name") or "").strip()
            saved_url = (result.get("saved_url") or "").strip()
            if not saved_name or not saved_url:
                continue
            cameras.append(
                {
                    "ip": ip,
                    "name": saved_name,
                    "url": saved_url,
                    "result": result,
                }
            )
        return cameras

    def _refresh_tray_menu(self) -> None:
        if self.saved_cameras_menu is None:
            return

        self.saved_cameras_menu.clear()
        cameras = self._saved_cameras()
        if not cameras:
            empty_action = QAction("Nenhuma camera salva", self)
            empty_action.setEnabled(False)
            self.saved_cameras_menu.addAction(empty_action)
            return

        for camera in cameras:
            camera_menu = self.saved_cameras_menu.addMenu(f"{camera['name']} ({camera['ip']})")
            open_action = QAction("Abrir video", self)
            open_action.triggered.connect(
                lambda checked=False, url=camera["url"], name=camera["name"]: self._open_saved_camera_from_tray(name, url)
            )
            camera_menu.addAction(open_action)

            if self._ptz_available(camera["result"]):
                ptz_menu = camera_menu.addMenu("PTZ")
                self._populate_tray_ptz_menu(ptz_menu, camera["ip"], camera["name"], camera["result"])

    def _sync_autostart(self) -> None:
        path = autostart_path()
        if not self.autostart_check.isChecked():
            try:
                path.unlink()
            except FileNotFoundError:
                pass
            except OSError:
                pass
            return

        desktop_entry = "\n".join(
            [
                "[Desktop Entry]",
                "Type=Application",
                "Name=Camera Discovery",
                "Comment=Descobrir e abrir cameras ONVIF/RTSP",
                "Exec=camera-discovery --start-minimized",
                "Icon=camera-discovery",
                "Terminal=false",
                "Categories=Network;Video;Utility;",
                "StartupNotify=false",
                "X-GNOME-Autostart-enabled=true",
                "",
            ]
        )
        try:
            path.write_text(desktop_entry, encoding="utf-8")
        except OSError:
            pass

    def _prune_player_processes(self) -> None:
        self.player_processes = [process for process in self.player_processes if process.poll() is None]

    def _close_player_processes(self) -> None:
        self._prune_player_processes()
        for process in self.player_processes:
            try:
                process.terminate()
            except OSError:
                pass

        for process in self.player_processes:
            try:
                process.wait(timeout=2)
            except (OSError, subprocess.TimeoutExpired):
                try:
                    process.kill()
                except OSError:
                    pass

        self.player_processes.clear()

    def on_camera_select(self) -> None:
        ip = self._selected_ip()
        if not ip:
            return

        result = self.results.get(ip)
        if not result:
            return

        self.url_list.clear()
        urls = []
        for stream in result.get("streams", []):
            profile = stream["profile"]
            label = f"ONVIF {profile['token']} -> {stream['url']}"
            urls.append((label, stream["url"]))

        for candidate in result.get("rtsp_candidates", []):
            label = f"RTSP {candidate['path']} [{candidate['status']}] -> {candidate['url']}"
            urls.append((label, candidate["url"]))

        for label, url in urls:
            item = QListWidgetItem(label)
            item.setData(Qt.UserRole, url)
            self.url_list.addItem(item)

        self.saved_name_edit.setText(result.get("saved_name", ""))
        display_url = result.get("saved_url") or guess_best_url(result) or ""
        self.url_edit.setText(display_url)
        self._refresh_ptz_widgets(result)
        if self._ptz_available(result):
            self._refresh_ptz_data_for_result(ip, result, self._ptz_info(result))

        lines = [f"IP: {ip}"]
        if result.get("error"):
            lines.append(f"Erro: {result['error']}")
        if result.get("onvif"):
            lines.append(f"ONVIF XAddr: {result['onvif'].get('xaddrs')}")
            lines.append(f"Types: {result['onvif'].get('types')}")
            if self._ptz_available(result):
                ptz_info = self._ptz_info(result)
                lines.append(f"PTZ: disponivel ({ptz_info.get('service_url')})")
            else:
                lines.append("PTZ: indisponivel")
        else:
            lines.append("ONVIF: sem resposta")

        if result.get("streams"):
            lines.append("")
            lines.append("Streams ONVIF:")
            for stream in result["streams"]:
                profile = stream["profile"]
                size = ""
                if profile.get("width") and profile.get("height"):
                    size = f" {profile['width']}x{profile['height']}"
                lines.append(f"- {profile['token']}{size}: {stream['plain_url']}")

        if result.get("rtsp_candidates"):
            lines.append("")
            lines.append("RTSP candidatos:")
            for candidate in result["rtsp_candidates"]:
                extra = f" auth={candidate['auth']}" if candidate.get("auth") else ""
                lines.append(f"- {candidate['path']} [{candidate['status']}]{extra}")

        lines.append("")
        lines.append("Se a URL automatica nao funcionar, edite o campo acima e abra manualmente.")
        self.detail_text.setPlainText("\n".join(lines))

    def on_url_select(self) -> None:
        item = self.url_list.currentItem()
        if not item:
            return
        url = item.data(Qt.UserRole)
        if url:
            self.url_edit.setText(url)
            self._persist_current_url()

    def use_best_url(self) -> None:
        ip = self._selected_ip()
        if not ip:
            QMessageBox.information(self, "Camera", "Selecione uma camera.")
            return

        best_url = guess_best_url(self.results.get(ip, {}))
        if not best_url:
            QMessageBox.information(self, "URL", "Nenhuma URL detectada automaticamente para esta camera.")
            return

        self.url_edit.setText(best_url)
        self._persist_current_url()

    def save_current_camera(self) -> None:
        ip = self._selected_ip()
        if not ip:
            QMessageBox.information(self, "Camera", "Selecione uma camera.")
            return

        saved_name = self.saved_name_edit.text().strip()
        url = self.url_edit.text().strip()
        if not saved_name:
            QMessageBox.information(self, "Nome", "Informe um nome para a camera.")
            return
        if not url:
            QMessageBox.information(self, "URL", "Informe uma URL para salvar a camera.")
            return

        self._persist_current_saved_name(save_cache=False)
        self._persist_current_url(save_cache=False)
        self._save_cached_results()
        self._save_config()
        self._set_status(f"Camera salva no tray: {saved_name}")

    def _open_url(self, url: str, title: str | None = None) -> None:
        try:
            max_delay_us = int(self.max_delay_edit.text() or "0")
        except ValueError:
            QMessageBox.critical(self, "max_delay", "max_delay(us) invalido.")
            return

        try:
            process = open_with_ffplay(
                url,
                transport=self.transport_combo.currentText(),
                max_delay_us=max_delay_us,
                disable_audio=self.disable_audio_check.isChecked(),
                always_on_top=True,
                window_title=title,
                borderless=True,
            )
            self._prune_player_processes()
            self.player_processes.append(process)
        except OSError as exc:
            QMessageBox.critical(self, "ffplay", f"Falha ao abrir ffplay: {exc}")

    def _open_saved_camera_from_tray(self, name: str, url: str) -> None:
        self._open_url(url, title=name)
        self._set_status(f"Abrindo camera salva: {name}")

    def _ptz_info(self, result: dict | None) -> dict:
        if not result:
            return {}
        onvif = result.get("onvif") or {}
        ptz = onvif.get("ptz")
        if not isinstance(ptz, dict):
            return {}
        info = dict(ptz)
        profiles = info.get("profiles") or []
        selected_profile = result.get("ptz_profile_token")
        if selected_profile in profiles:
            info["profile_token"] = selected_profile
        elif profiles and not info.get("profile_token"):
            info["profile_token"] = profiles[0]
        return info

    def _ptz_available(self, result: dict | None) -> bool:
        return bool(self._ptz_info(result).get("available"))

    def _ptz_selected_profile(self, result: dict | None) -> str | None:
        return self._ptz_info(result).get("profile_token") if result else None

    def _ptz_presets_for_selected_profile(self, result: dict | None) -> list[dict]:
        if not result:
            return []
        selected = self._ptz_selected_profile(result)
        by_profile = result.get("ptz_presets_by_profile")
        if isinstance(by_profile, dict) and selected:
            return list(by_profile.get(selected, []))
        return list(result.get("ptz_presets", []))

    def _set_ptz_presets_for_selected_profile(self, result: dict, presets: list[dict]) -> None:
        selected = self._ptz_selected_profile(result)
        if not selected:
            result["ptz_presets"] = presets
            return
        by_profile = result.get("ptz_presets_by_profile")
        if not isinstance(by_profile, dict):
            by_profile = {}
        by_profile[selected] = presets
        result["ptz_presets_by_profile"] = by_profile
        result["ptz_presets"] = presets

    def _refresh_ptz_widgets(self, result: dict | None) -> None:
        self.ptz_preset_list.clear()
        if not result or not self._ptz_available(result):
            self.ptz_status_label.setText("PTZ: indisponivel.")
            self.ptz_profile_label.setText("Profile PTZ: -")
            self.ptz_presets_info_label.setText("Presets PTZ: -")
            self.ptz_debug_label.setText("Debug PTZ: -")
            self.ptz_profile_combo.blockSignals(True)
            self.ptz_profile_combo.clear()
            self.ptz_profile_combo.blockSignals(False)
            self.ptz_preset_name_edit.clear()
            return

        ptz_info = self._ptz_info(result)
        self.ptz_profile_label.setText(f"Profile PTZ: {ptz_info.get('profile_token') or '-'}")
        profiles = ptz_info.get("profiles") or []
        self.ptz_profile_combo.blockSignals(True)
        self.ptz_profile_combo.clear()
        self.ptz_profile_combo.addItems(profiles)
        current_profile = ptz_info.get("profile_token") or ""
        index = self.ptz_profile_combo.findText(current_profile)
        self.ptz_profile_combo.setCurrentIndex(index if index >= 0 else 0)
        self.ptz_profile_combo.blockSignals(False)
        selected_presets = self._ptz_presets_for_selected_profile(result)
        self.ptz_presets_info_label.setText(
            f"Presets PTZ: {len(selected_presets)} no {current_profile or '-'}"
        )
        preset_tokens = ", ".join(preset.get("token", "?") for preset in selected_presets[:6]) or "-"
        self.ptz_debug_label.setText(
            "Debug PTZ: selected={} active={} queried={} count={} tokens={}".format(
                result.get("ptz_profile_token") or "-",
                current_profile or "-",
                result.get("ptz_last_query_profile") or "-",
                result.get("ptz_last_query_count", "-"),
                preset_tokens,
            )
        )
        status = result.get("ptz_status")
        if status:
            self.ptz_status_label.setText(
                "PTZ: pan={:.3f} tilt={:.3f} zoom={:.3f}".format(
                    status.get("pan", 0.0),
                    status.get("tilt", 0.0),
                    status.get("zoom", 0.0),
                )
            )
        else:
            self.ptz_status_label.setText("PTZ: disponivel. Clique em Atualizar PTZ para ler a posicao.")

        for preset in selected_presets:
            label = preset["name"]
            if preset.get("token"):
                label = f"{label} ({preset['token']})"
            item = QListWidgetItem(label)
            item.setData(Qt.UserRole, preset)
            self.ptz_preset_list.addItem(item)

    def _selected_ptz_context(self) -> tuple[str, dict, dict] | None:
        ip = self._selected_ip()
        if not ip:
            QMessageBox.information(self, "PTZ", "Selecione uma camera.")
            return None

        result = self.results.get(ip)
        if not result or not self._ptz_available(result):
            QMessageBox.information(self, "PTZ", "PTZ nao esta disponivel para a camera selecionada.")
            return None

        return ip, result, self._ptz_info(result)

    def on_ptz_profile_changed(self, profile_token: str) -> None:
        if not profile_token:
            return

        ip = self._selected_ip()
        if not ip:
            return

        result = self.results.get(ip)
        if not result or not self._ptz_available(result):
            return

        if result.get("ptz_profile_token") == profile_token:
            return

        result["ptz_profile_token"] = profile_token
        self._set_ptz_presets_for_selected_profile(result, [])
        result.pop("ptz_status", None)
        self._refresh_ptz_widgets(result)
        self._refresh_ptz_data_for_result(ip, result, self._ptz_info(result))
        self._set_status(f"Profile PTZ alterado para {profile_token}.")

    def _refresh_ptz_data_for_result(self, ip: str, result: dict, ptz_info: dict) -> None:
        credentials = self._ptz_credentials()
        if credentials is None:
            return

        username, password, timeout = credentials
        result["ptz_last_query_profile"] = ptz_info.get("profile_token")
        status = ptz_get_status(ptz_info["service_url"], username, password, ptz_info["profile_token"], timeout)
        if status:
            result["ptz_status"] = status
        presets = ptz_get_presets(
            ptz_info["service_url"],
            username,
            password,
            ptz_info["profile_token"],
            timeout,
        )
        result["ptz_last_query_count"] = len(presets)
        self._set_ptz_presets_for_selected_profile(result, presets)
        if ip == self._selected_ip():
            self._refresh_ptz_widgets(result)
        self._save_cached_results()

    def _ptz_credentials(self) -> tuple[str, str, float] | None:
        username = self.user_edit.text().strip() or "admin"
        password = self.password_edit.text()
        if password is None:
            password = ""
        if not password:
            QMessageBox.information(self, "PTZ", "Informe a senha da camera para controlar PTZ.")
            return None

        try:
            timeout = float(self.timeout_edit.text())
        except ValueError:
            QMessageBox.critical(self, "Timeout", "Timeout invalido.")
            return None

        return username, password, timeout

    def refresh_selected_ptz_status(self) -> None:
        context = self._selected_ptz_context()
        if context is None:
            return

        ip, result, ptz_info = context
        self._refresh_ptz_data_for_result(ip, result, ptz_info)
        self._set_status(f"Status PTZ atualizado para {ip}.")

    def refresh_selected_ptz_presets(self) -> None:
        context = self._selected_ptz_context()
        if context is None:
            return

        credentials = self._ptz_credentials()
        if credentials is None:
            return

        ip, result, ptz_info = context
        username, password, timeout = credentials
        self._set_ptz_presets_for_selected_profile(result, ptz_get_presets(
            ptz_info["service_url"],
            username,
            password,
            ptz_info["profile_token"],
            timeout,
        ))
        self._refresh_ptz_widgets(result)
        self._save_cached_results()
        self._set_status(f"Presets PTZ atualizados para {ip}.")

    def _move_selected_camera_ptz(self, pan: float, tilt: float, zoom: float = 0.0) -> None:
        context = self._selected_ptz_context()
        if context is None:
            return

        credentials = self._ptz_credentials()
        if credentials is None:
            return

        ip, result, ptz_info = context
        username, password, timeout = credentials
        ok = ptz_relative_move(
            ptz_info["service_url"],
            username,
            password,
            ptz_info["profile_token"],
            timeout,
            pan=pan,
            tilt=tilt,
            zoom=zoom,
        )
        if not ok:
            QMessageBox.warning(self, "PTZ", "A camera recusou o comando PTZ.")
            return

        self._set_status(f"Comando PTZ enviado para {ip}.")
        status = ptz_get_status(ptz_info["service_url"], username, password, ptz_info["profile_token"], timeout)
        if status:
            result["ptz_status"] = status
        self._refresh_ptz_widgets(result)
        self._save_cached_results()

    def save_selected_ptz_preset(self) -> None:
        context = self._selected_ptz_context()
        if context is None:
            return

        credentials = self._ptz_credentials()
        if credentials is None:
            return

        ip, result, ptz_info = context
        preset_name = self.ptz_preset_name_edit.text().strip()
        if not preset_name:
            QMessageBox.information(self, "Preset", "Informe um nome para a posicao.")
            return

        username, password, timeout = credentials
        preset_token = ptz_set_preset(
            ptz_info["service_url"],
            username,
            password,
            ptz_info["profile_token"],
            preset_name,
            timeout,
        )
        if not preset_token:
            QMessageBox.warning(self, "Preset", "Nao foi possivel salvar o preset ONVIF na camera.")
            return

        self._set_ptz_presets_for_selected_profile(result, ptz_get_presets(
            ptz_info["service_url"],
            username,
            password,
            ptz_info["profile_token"],
            timeout,
        ))
        self._refresh_ptz_widgets(result)
        self._save_cached_results()
        self._set_status(f"Preset ONVIF salvo para {ip}: {preset_name}")

    def goto_selected_ptz_preset(self) -> None:
        context = self._selected_ptz_context()
        if context is None:
            return

        item = self.ptz_preset_list.currentItem()
        if item is None:
            QMessageBox.information(self, "Preset", "Selecione um preset salvo.")
            return

        preset = item.data(Qt.UserRole)
        if not isinstance(preset, dict):
            return

        self._goto_ptz_preset(context[0], context[1], context[2], preset)

    def delete_selected_ptz_preset(self) -> None:
        context = self._selected_ptz_context()
        if context is None:
            return

        item = self.ptz_preset_list.currentItem()
        if item is None:
            QMessageBox.information(self, "Preset", "Selecione um preset salvo.")
            return

        preset = item.data(Qt.UserRole)
        if not isinstance(preset, dict):
            return

        result = context[1]
        ptz_info = context[2]
        credentials = self._ptz_credentials()
        if credentials is None:
            return

        token = preset.get("token")
        if not token:
            QMessageBox.warning(self, "Preset", "Preset sem token ONVIF.")
            return

        username, password, timeout = credentials
        ok = ptz_remove_preset(
            ptz_info["service_url"],
            username,
            password,
            ptz_info["profile_token"],
            token,
            timeout,
        )
        if not ok:
            QMessageBox.warning(self, "Preset", "Nao foi possivel remover o preset ONVIF da camera.")
            return

        self._set_ptz_presets_for_selected_profile(result, ptz_get_presets(
            ptz_info["service_url"],
            username,
            password,
            ptz_info["profile_token"],
            timeout,
        ))
        self._refresh_ptz_widgets(result)
        self._save_cached_results()
        self._set_status(f"Preset removido: {preset.get('name')}")

    def _goto_ptz_preset(self, ip: str, result: dict, ptz_info: dict, preset: dict) -> None:
        credentials = self._ptz_credentials()
        if credentials is None:
            return

        username, password, timeout = credentials
        token = preset.get("token")
        if not token:
            QMessageBox.warning(self, "Preset", "Preset sem token ONVIF.")
            return

        ok = ptz_goto_preset(
            ptz_info["service_url"],
            username,
            password,
            ptz_info["profile_token"],
            token,
            timeout,
        )
        if not ok:
            QMessageBox.warning(self, "Preset", "A camera recusou o movimento para o preset salvo.")
            return

        status = ptz_get_status(ptz_info["service_url"], username, password, ptz_info["profile_token"], timeout)
        if status:
            result["ptz_status"] = status
        self._refresh_ptz_widgets(result)
        self._save_cached_results()
        self._set_status(f"Camera {ip} movida para o preset {preset.get('name')}.")

    def _save_tray_ptz_preset(self, ip: str, result: dict) -> None:
        ptz_info = self._ptz_info(result)
        if not ptz_info:
            return

        name, ok = QInputDialog.getText(self, "Salvar preset PTZ", f"Nome do preset para {ip}:")
        if not ok or not name.strip():
            return

        credentials = self._ptz_credentials()
        if credentials is None:
            return

        username, password, timeout = credentials
        preset_token = ptz_set_preset(
            ptz_info["service_url"],
            username,
            password,
            ptz_info["profile_token"],
            name.strip(),
            timeout,
        )
        if not preset_token:
            QMessageBox.warning(self, "Preset", "Nao foi possivel salvar o preset ONVIF na camera.")
            return

        self._set_ptz_presets_for_selected_profile(result, ptz_get_presets(
            ptz_info["service_url"],
            username,
            password,
            ptz_info["profile_token"],
            timeout,
        ))
        self._save_cached_results()
        if ip == self._selected_ip():
            self._refresh_ptz_widgets(result)
        self._set_status(f"Preset ONVIF salvo para {ip}: {name.strip()}")

    def _populate_tray_ptz_menu(self, menu: QMenu, ip: str, name: str, result: dict) -> None:
        for label, pan, tilt, zoom in [
            ("Cima", 0.0, -0.1, 0.0),
            ("Baixo", 0.0, 0.1, 0.0),
            ("Esquerda", -0.1, 0.0, 0.0),
            ("Direita", 0.1, 0.0, 0.0),
            ("Zoom +", 0.0, 0.0, 0.1),
            ("Zoom -", 0.0, 0.0, -0.1),
        ]:
            action = QAction(label, self)
            action.triggered.connect(
                lambda checked=False, camera_ip=ip, camera_name=name, camera_result=result, p=pan, t=tilt, z=zoom:
                self._tray_ptz_move(camera_ip, camera_name, camera_result, p, t, z)
            )
            menu.addAction(action)

        menu.addSeparator()
        save_action = QAction("Salvar posicao atual...", self)
        save_action.triggered.connect(lambda checked=False, camera_ip=ip, camera_result=result: self._save_tray_ptz_preset(camera_ip, camera_result))
        menu.addAction(save_action)

        presets_menu = menu.addMenu("Presets")
        presets = result.get("ptz_presets", [])
        if not presets:
            empty_action = QAction("Nenhum preset salvo", self)
            empty_action.setEnabled(False)
            presets_menu.addAction(empty_action)
        else:
            for preset in presets:
                preset_action = QAction(preset["name"], self)
                preset_action.triggered.connect(
                    lambda checked=False, camera_ip=ip, camera_result=result, preset_data=preset:
                    self._tray_ptz_goto_preset(camera_ip, camera_result, preset_data)
                )
                presets_menu.addAction(preset_action)

    def _tray_ptz_move(self, ip: str, name: str, result: dict, pan: float, tilt: float, zoom: float) -> None:
        ptz_info = self._ptz_info(result)
        if not ptz_info:
            return

        credentials = self._ptz_credentials()
        if credentials is None:
            return

        username, password, timeout = credentials
        ok = ptz_relative_move(
            ptz_info["service_url"],
            username,
            password,
            ptz_info["profile_token"],
            timeout,
            pan=pan,
            tilt=tilt,
            zoom=zoom,
        )
        if not ok:
            QMessageBox.warning(self, "PTZ", f"A camera {name} recusou o comando PTZ.")
            return

        status = ptz_get_status(ptz_info["service_url"], username, password, ptz_info["profile_token"], timeout)
        if status:
            result["ptz_status"] = status
        if ip == self._selected_ip():
            self._refresh_ptz_widgets(result)
        self._save_cached_results()
        self._set_status(f"Comando PTZ enviado para {name}.")

    def _tray_ptz_goto_preset(self, ip: str, result: dict, preset: dict) -> None:
        ptz_info = self._ptz_info(result)
        if not ptz_info:
            return
        self._goto_ptz_preset(ip, result, ptz_info, preset)

    def show_about(self) -> None:
        QMessageBox.information(
            self,
            "Sobre",
            "\n".join(
                [
                    "Camera Discovery",
                    "",
                    f"Autor: {AUTHOR_NAME}",
                    f"Email: {AUTHOR_EMAIL}",
                ]
            ),
        )

    def open_selected_url(self) -> None:
        url = self.url_edit.text().strip()
        if not url:
            QMessageBox.critical(self, "URL", "Informe uma URL RTSP para abrir.")
            return
        self._persist_current_url()
        self._save_config()

        ip = self._selected_ip()
        title = None
        if ip:
            result = self.results.get(ip)
            if result:
                name = result.get("saved_name")
                if name:
                    title = f"{name} ({ip})"
                else:
                    title = ip

        self._open_url(url, title=title)

    def copy_url(self) -> None:
        url = self.url_edit.text().strip()
        if not url:
            return
        self._persist_current_url()
        self._save_config()
        QApplication.clipboard().setText(url)
        self._set_status("URL copiada.")

    def minimize_to_tray(self) -> None:
        self._save_config()
        if not self.tray_available or self.tray_icon is None:
            self.showMinimized()
            self._set_status("Tray indisponivel. Janela minimizada normalmente.")
            return
        self.hide()
        self._set_status("Aplicacao minimizada para o tray.")

    def restore_from_tray(self) -> None:
        self.showNormal()
        self.raise_()
        self.activateWindow()

    def shutdown(self) -> None:
        self._save_config()
        self._close_player_processes()
        if self.tray_icon is not None:
            self.tray_icon.hide()
        QApplication.quit()

    def closeEvent(self, event: QCloseEvent) -> None:
        self._save_config()
        if self.minimize_to_tray_check.isChecked() and self.tray_available and self.tray_icon is not None:
            event.ignore()
            self.minimize_to_tray()
            return
        self._close_player_processes()
        super().closeEvent(event)


def main() -> None:
    start_minimized = "--start-minimized" in sys.argv[1:]
    app = QApplication(sys.argv)
    app.setQuitOnLastWindowClosed(False)
    window = CameraDiscoveryWindow(start_minimized=start_minimized)
    if start_minimized and window.tray_available:
        window.hide()
        window._set_status("Aplicacao iniciada no tray.")
    else:
        window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
