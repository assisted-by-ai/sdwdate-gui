"""Helpers to provide PyQt5 stand-ins for the test suite."""

import sys
import types
from pathlib import Path


def _ensure_module(name: str) -> types.ModuleType:
    module = types.ModuleType(name)
    sys.modules[name] = module
    return module


def ensure_pyqt5() -> None:
    """Install lightweight PyQt5 shims if the real bindings are unavailable."""

    if "PyQt5" in sys.modules:
        return

    pyqt5 = _ensure_module("PyQt5")

    class _Signal:
        def __init__(self) -> None:
            self._slots: list = []

        def connect(self, slot) -> None:  # noqa: D401 - mimic Qt signal API
            self._slots.append(slot)

        def emit(self, *args, **kwargs) -> None:
            for slot in list(self._slots):
                slot(*args, **kwargs)

    class _QObject:
        def __init__(self, *_, **__):
            pass

    qtcore = _ensure_module("PyQt5.QtCore")
    qtcore.pyqtSignal = lambda *_, **__: _Signal()  # type: ignore[assignment]
    qtcore.Qt = type("Qt", (), {})
    qtcore.QObject = _QObject
    qtcore.QTimer = type("QTimer", (), {})
    pyqt5.QtCore = qtcore

    def _dummy_class(name: str):
        return type(name, (), {"__init__": lambda self, *_, **__: None})

    qtgui = _ensure_module("PyQt5.QtGui")
    for cls_name in ("QIcon", "QImage", "QCursor", "QPixmap"):
        setattr(qtgui, cls_name, _dummy_class(cls_name))
    pyqt5.QtGui = qtgui

    qtwidgets = _ensure_module("PyQt5.QtWidgets")
    for cls_name in (
        "QMenu",
        "QAction",
        "QApplication",
        "QDialog",
        "QWidget",
        "QLabel",
        "QPushButton",
        "QGridLayout",
    ):
        setattr(qtwidgets, cls_name, _dummy_class(cls_name))

    class _SystemTrayIcon(_dummy_class("QSystemTrayIcon")):
        ActivationReason = type("ActivationReason", (), {})

        def __init__(self, *_, **__):
            super().__init__()

        def showMessage(self, *_, **__):  # pragma: no cover - placeholder
            pass

    qtwidgets.QSystemTrayIcon = _SystemTrayIcon
    pyqt5.QtWidgets = qtwidgets

    class _DummySocket:
        ConnectedState = object()

        def __init__(self, *_, **__):
            self._ready_read = _Signal()
            self._disconnected = _Signal()

        def setParent(self, *_):
            pass

        @property
        def readyRead(self):  # noqa: D401 - mimic PyQt signal property
            return self._ready_read

        @property
        def disconnected(self):  # noqa: D401 - mimic PyQt signal property
            return self._disconnected

        def state(self):  # pragma: no cover - minimal behaviour
            return self.ConnectedState

        def readAll(self):  # pragma: no cover - placeholder return shape
            return types.SimpleNamespace(data=lambda: b"")

        def write(self, *_):  # pragma: no cover - placeholder
            pass

        def flush(self):  # pragma: no cover - placeholder
            pass

    qtnetwork = _ensure_module("PyQt5.QtNetwork")
    qtnetwork.QLocalSocket = _DummySocket
    qtnetwork.QLocalServer = _dummy_class("QLocalServer")
    pyqt5.QtNetwork = qtnetwork


def add_dist_packages_to_path() -> None:
    """Ensure the package directory is importable for tests."""

    dist_path = (
        Path(__file__).resolve().parents[1]
        / "usr"
        / "lib"
        / "python3"
        / "dist-packages"
    )
    str_path = str(dist_path)
    if str_path not in sys.path:
        sys.path.insert(0, str_path)
