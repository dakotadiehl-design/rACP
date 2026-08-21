from __future__ import annotations

import asyncio
import json
import threading

from PySide6.QtCore import QObject, Qt, QTimer, Signal
from PySide6.QtWidgets import (
    QApplication,
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QSplitter,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from .config import is_loopback_target
from .engine import WorkbenchEngine
from .models import ConnectionConfig
from .profiles import PROFILE_TYPES
from .reports import console_summary
from .scenarios import ScenarioRunner, load_scenario


class EngineController(QObject):
    changed = Signal()
    failed = Signal(str)
    scenario_finished = Signal(str)

    def __init__(self) -> None:
        super().__init__()
        self.loop = asyncio.new_event_loop()
        self.engine = WorkbenchEngine()
        self.thread = threading.Thread(target=self.loop.run_forever, name="acp-workbench-engine", daemon=True)
        self.thread.start()

    def submit(self, coroutine) -> None:
        future = asyncio.run_coroutine_threadsafe(coroutine, self.loop)
        future.add_done_callback(self._done)

    def _done(self, future) -> None:
        try:
            future.result()
        except Exception as exc:
            self.failed.emit(f"{type(exc).__name__}: {exc}")
        self.changed.emit()

    def connect(self, target: str, profile: str, allow_plaintext: bool) -> None:
        config = ConnectionConfig(target=target, profile=profile, allow_plaintext=allow_plaintext)
        self.submit(self.engine.connect(config))

    def disconnect(self) -> None:
        self.submit(self.engine.disconnect("default"))

    def invoke(self, control_id: str, *, interaction: str = "activate", value=None) -> None:
        self.submit(self.engine.invoke("default", control_id, value, interaction=interaction))

    def momentary(self, control_id: str, duration: float) -> None:
        self.submit(self.engine.momentary("default", control_id, duration=duration))

    def run_scenario(self, path: str, config: ConnectionConfig) -> None:
        async def run() -> None:
            import time

            from .models import RunResult, utc_now_text

            scenario = load_scenario(path)
            started_at = utc_now_text()
            started = time.monotonic()
            result = await ScenarioRunner(self.engine).run(scenario, config)
            run_result = RunResult(
                result.passed,
                [result],
                started_at,
                time.monotonic() - started,
            )
            self.scenario_finished.emit(console_summary(run_result))

        self.submit(run())

    def shutdown(self) -> None:
        future = asyncio.run_coroutine_threadsafe(self.engine.close(), self.loop)
        try:
            future.result(timeout=3)
        finally:
            self.loop.call_soon_threadsafe(self.loop.stop)
            self.thread.join(timeout=3)


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("ACP Workbench")
        self.resize(1100, 700)
        self.controller = EngineController()
        self.controller.failed.connect(self._error)
        self.controller.changed.connect(self.refresh)
        self.controller.scenario_finished.connect(self._scenario_finished)
        self._seen = 0

        self.target = QLineEdit("ws://127.0.0.1:27421/acp")
        self.profile = QComboBox()
        self.profile.addItems(sorted(PROFILE_TYPES))
        self.connect_button = QPushButton("Connect")
        self.disconnect_button = QPushButton("Disconnect")
        self.scenario_button = QPushButton("Run Scenario…")
        self.status = QLabel("Disconnected")
        self.actions = QListWidget()
        self.messages = QTextEdit()
        self.messages.setReadOnly(True)
        self.detail = QTextEdit()
        self.detail.setReadOnly(True)

        top = QHBoxLayout()
        top.addWidget(QLabel("Target"))
        top.addWidget(self.target, 1)
        top.addWidget(self.profile)
        top.addWidget(self.connect_button)
        top.addWidget(self.disconnect_button)
        top.addWidget(self.scenario_button)
        top.addWidget(self.status)

        splitter = QSplitter()
        splitter.addWidget(self.actions)
        splitter.addWidget(self.messages)
        splitter.addWidget(self.detail)
        splitter.setSizes([220, 430, 430])

        layout = QVBoxLayout()
        layout.addLayout(top)
        layout.addWidget(splitter, 1)
        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)

        self.connect_button.clicked.connect(self._connect)
        self.disconnect_button.clicked.connect(self.controller.disconnect)
        self.scenario_button.clicked.connect(self._run_scenario)
        self.actions.itemDoubleClicked.connect(self._invoke_action)
        self.messages.cursorPositionChanged.connect(self._show_selected)
        timer = QTimer(self)
        timer.timeout.connect(self.refresh)
        timer.start(200)
        self._timer = timer

    def refresh(self) -> None:
        history = self.controller.engine.history
        for event in history[self._seen:]:
            envelope = event.data.get("envelope")
            if envelope:
                arrow = "←" if event.kind == "envelope.in" else "→"
                self.messages.append(f"{event.sequence:05d} {arrow} {envelope.get('type')}")
            elif event.kind.startswith("connection"):
                self.messages.append(f"{event.sequence:05d} {event.kind}: {event.data}")
        self._seen = len(history)
        connection = self.controller.engine.connections.get("default")
        self.status.setText(connection.state.value if connection else "disconnected")
        current = {self.actions.item(i).data(256) for i in range(self.actions.count())}
        if connection:
            for action in connection.profile.actions():
                if action.id not in current:
                    item = QListWidgetItem(action.label)
                    item.setData(256, action.id)
                    if not action.enabled or not action.available:
                        item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEnabled)
                        item.setToolTip(action.reason or "Control is unavailable")
                    self.actions.addItem(item)

    def _show_selected(self) -> None:
        cursor = self.messages.textCursor()
        line = cursor.block().text().split(maxsplit=2)
        if not line:
            return
        try:
            sequence = int(line[0])
            event = next(item for item in self.controller.engine.history if item.sequence == sequence)
        except (ValueError, StopIteration):
            return
        self.detail.setPlainText(json.dumps(event.to_dict(), indent=2, default=str))

    def _error(self, message: str) -> None:
        QMessageBox.critical(self, "ACP Workbench", message)

    def _connect(self) -> None:
        target = self.target.text()
        if not is_loopback_target(target):
            answer = QMessageBox.warning(
                self,
                "Non-loopback ACP target",
                "This target may control a live system. Continue?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            if answer != QMessageBox.StandardButton.Yes:
                return
        self.controller.connect(target, self.profile.currentText(), target.startswith("ws://"))

    def _invoke_action(self, item: QListWidgetItem) -> None:
        connection = self.controller.engine.connections.get("default")
        if connection is None:
            return
        action_id = str(item.data(256))
        definition = next((action for action in connection.profile.actions() if action.id == action_id), None)
        if definition and (not definition.enabled or not definition.available):
            return
        if definition and definition.dangerous:
            answer = QMessageBox.warning(
                self,
                "Safety-sensitive action",
                f"Send {definition.label}? Prism remains authoritative.",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            if answer != QMessageBox.StandardButton.Yes:
                return
        kind = definition.kind if definition else "button"
        if kind == "toggle":
            state = connection.profile.view.get(f"control.{action_id}") or {}
            self.controller.invoke(action_id, interaction="set", value=not bool(state.get("value")))
        elif kind in {"slider", "encoder"}:
            minimum = definition.minimum if definition and definition.minimum is not None else 0.0
            maximum = definition.maximum if definition and definition.maximum is not None else 1.0
            value, accepted = QInputDialog.getDouble(
                self,
                definition.label if definition else action_id,
                "Desired value",
                minimum,
                minimum,
                maximum,
                3,
            )
            if accepted:
                self.controller.invoke(action_id, interaction="set", value=value)
        elif kind == "momentary":
            duration, accepted = QInputDialog.getDouble(
                self,
                definition.label if definition else action_id,
                "Hold duration (seconds)",
                1.0,
                0.05,
                30.0,
                2,
            )
            if accepted:
                self.controller.momentary(action_id, duration)
        else:
            self.controller.invoke(action_id)

    def _run_scenario(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Run ACP scenario",
            "",
            "ACP scenarios (*.json *.yaml *.yml)",
        )
        if not path:
            return
        config = ConnectionConfig(
            target=self.target.text(),
            profile=self.profile.currentText(),
            allow_plaintext=self.target.text().startswith("ws://"),
        )
        self.controller.run_scenario(path, config)

    def _scenario_finished(self, summary: str) -> None:
        self.detail.setPlainText(summary)

    def closeEvent(self, event) -> None:
        self.controller.shutdown()
        event.accept()


def run_gui() -> int:
    app = QApplication.instance() or QApplication([])
    window = MainWindow()
    window.show()
    return app.exec()
