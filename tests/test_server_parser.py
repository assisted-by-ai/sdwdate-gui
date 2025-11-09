import sys
import types
from pathlib import Path
import unittest

# Provide minimal PyQt5 shims so the server module can be imported without the
# actual GUI dependencies being present in the test environment.
if "PyQt5" not in sys.modules:  # pragma: no cover - executed during import
    pyqt5 = types.ModuleType("PyQt5")
    sys.modules["PyQt5"] = pyqt5

    class _Signal:
        def __init__(self) -> None:
            self._slots: list = []

        def connect(self, slot) -> None:  # noqa: D401 - match PyQt interface
            self._slots.append(slot)

        def emit(self, *args, **kwargs) -> None:
            for slot in list(self._slots):
                slot(*args, **kwargs)

    class _QObject:
        def __init__(self, *_, **__):
            pass

    qtcore = types.ModuleType("PyQt5.QtCore")
    qtcore.pyqtSignal = lambda *_, **__: _Signal()  # type: ignore[assignment]
    qtcore.Qt = type("Qt", (), {})
    qtcore.QObject = _QObject
    qtcore.QTimer = type("QTimer", (), {})
    sys.modules["PyQt5.QtCore"] = qtcore
    pyqt5.QtCore = qtcore

    def _dummy_class(name: str):
        return type(name, (), {"__init__": lambda self, *_, **__: None})

    qtgui = types.ModuleType("PyQt5.QtGui")
    for cls_name in ("QIcon", "QImage", "QCursor", "QPixmap"):
        setattr(qtgui, cls_name, _dummy_class(cls_name))
    sys.modules["PyQt5.QtGui"] = qtgui
    pyqt5.QtGui = qtgui

    qtwidgets = types.ModuleType("PyQt5.QtWidgets")
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

    qtwidgets.QSystemTrayIcon = _SystemTrayIcon
    sys.modules["PyQt5.QtWidgets"] = qtwidgets
    pyqt5.QtWidgets = qtwidgets

    class _DummySocket:
        def __init__(self, *_, **__):
            self._ready_read = _Signal()
            self._disconnected = _Signal()

        def setParent(self, *_):
            pass

        @property
        def readyRead(self):  # noqa: D401 - mimic PyQt signal
            return self._ready_read

        @property
        def disconnected(self):  # noqa: D401 - mimic PyQt signal
            return self._disconnected

        def readAll(self):
            return types.SimpleNamespace(data=lambda: b"")

    qtnetwork = types.ModuleType("PyQt5.QtNetwork")
    qtnetwork.QLocalSocket = _DummySocket
    qtnetwork.QLocalServer = _dummy_class("QLocalServer")
    sys.modules["PyQt5.QtNetwork"] = qtnetwork
    pyqt5.QtNetwork = qtnetwork

sys.path.insert(
    0,
    str(Path(__file__).resolve().parents[1] / "usr" / "lib" / "python3" / "dist-packages"),
)

from sdwdate_gui.sdwdate_gui_server import SdwdateGuiClient


class FragmentedMessageParsingTests(unittest.TestCase):
    """Tests for the server parser handling of fragmented messages."""

    def setUp(self) -> None:
        self.client = object.__new__(SdwdateGuiClient)
        # ensure the parser operates on a clean buffer
        self.client._SdwdateGuiClient__sock_buf = b""  # type: ignore[attr-defined]
        # the Qubes header parsing is not under test here
        self.client.qubes_header_parsed = True  # type: ignore[attr-defined]

        self.kicked = False

        def kick_client() -> None:
            self.kicked = True

        self.client.kick_client = kick_client  # type: ignore[assignment]
        self.client.client_name_or_unknown = lambda: "test-client"  # type: ignore[assignment]

        self.recorded_calls: list[tuple[str, str]] = []

        def fake_set_client_name(client_name: str) -> bool:
            self.recorded_calls.append(("set_client_name", client_name))
            return True

        self.client._SdwdateGuiClient__set_client_name = fake_set_client_name  # type: ignore[attr-defined]
        self.client._SdwdateGuiClient__set_sdwdate_status = lambda *_: True  # type: ignore[attr-defined]
        self.client._SdwdateGuiClient__set_tor_status = lambda *_: True  # type: ignore[attr-defined]

    def test_partial_message_keeps_header_in_buffer(self) -> None:
        payload = b"set_client_name foo"
        header = len(payload).to_bytes(2, byteorder="big")
        partial = header + payload[:5]

        self.client._SdwdateGuiClient__sock_buf = partial  # type: ignore[attr-defined]
        self.client._SdwdateGuiClient__try_parse_commands()  # type: ignore[attr-defined]

        self.assertEqual(self.client._SdwdateGuiClient__sock_buf, partial)  # type: ignore[attr-defined]
        self.assertFalse(self.kicked)
        self.assertEqual(self.recorded_calls, [])

    def test_fragmented_message_parses_once_complete(self) -> None:
        payload = b"set_client_name foo"
        header = len(payload).to_bytes(2, byteorder="big")

        first_chunk = header + payload[:8]
        remainder = payload[8:]

        self.client._SdwdateGuiClient__sock_buf = first_chunk  # type: ignore[attr-defined]
        self.client._SdwdateGuiClient__try_parse_commands()  # type: ignore[attr-defined]
        self.assertEqual(self.client._SdwdateGuiClient__sock_buf, first_chunk)  # type: ignore[attr-defined]
        self.assertEqual(self.recorded_calls, [])

        self.client._SdwdateGuiClient__sock_buf += remainder  # type: ignore[attr-defined]
        self.client._SdwdateGuiClient__try_parse_commands()  # type: ignore[attr-defined]

        self.assertEqual(self.client._SdwdateGuiClient__sock_buf, b"")  # type: ignore[attr-defined]
        self.assertEqual(self.recorded_calls, [("set_client_name", "foo")])
        self.assertFalse(self.kicked)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
