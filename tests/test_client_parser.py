import asyncio
import sys
import types
import unittest
from unittest import mock

# Provide minimal pyinotify shims so the client module can be imported without
# the actual dependency being present in the test environment.
if "pyinotify" not in sys.modules:  # pragma: no cover - executed during import
    pyinotify = types.ModuleType("pyinotify")

    class _ProcessEvent:  # pragma: no cover - attribute placeholder
        pass

    class _Event:  # pragma: no cover - attribute placeholder
        pathname = ""

    class _AsyncioNotifier:  # pragma: no cover - attribute placeholder
        def __init__(self, *_, **__):
            pass

    class _WatchManager:  # pragma: no cover - attribute placeholder
        def __init__(self, *_, **__):
            pass

    pyinotify.ProcessEvent = _ProcessEvent
    pyinotify.Event = _Event
    pyinotify.AsyncioNotifier = _AsyncioNotifier
    pyinotify.WatchManager = _WatchManager

    sys.modules["pyinotify"] = pyinotify

sys.path.insert(0, "usr/lib/python3/dist-packages")

from sdwdate_gui import sdwdate_gui_client as client


class FragmentedClientMessageParsingTests(unittest.TestCase):
    """Tests for the client parser handling of fragmented messages."""

    def setUp(self) -> None:
        self.recorded_calls: list[str] = []

        def record_call(name: str) -> None:
            self.recorded_calls.append(name)

        client.GlobalData.sock_buf = b""

        client.open_tor_control_panel = lambda: record_call("open_tor_control_panel")
        client.open_sdwdate_log = lambda: record_call("open_sdwdate_log")
        client.restart_sdwdate = lambda: record_call("restart_sdwdate")
        client.stop_sdwdate = lambda: record_call("stop_sdwdate")
        client.suppress_client_reconnect = lambda: record_call(
            "suppress_client_reconnect"
        )

    def test_partial_message_keeps_header_in_buffer(self) -> None:
        payload = b"open_tor_control_panel"
        header = len(payload).to_bytes(2, byteorder="big")
        partial = header + payload[:5]

        client.GlobalData.sock_buf = partial
        asyncio.run(client.try_parse_commands())

        self.assertEqual(client.GlobalData.sock_buf, partial)
        self.assertEqual(self.recorded_calls, [])

    def test_fragmented_message_parses_once_complete(self) -> None:
        payload = b"open_sdwdate_log"
        header = len(payload).to_bytes(2, byteorder="big")

        first_chunk = header + payload[:6]
        remainder = payload[6:]

        client.GlobalData.sock_buf = first_chunk
        asyncio.run(client.try_parse_commands())
        self.assertEqual(client.GlobalData.sock_buf, first_chunk)
        self.assertEqual(self.recorded_calls, [])

        client.GlobalData.sock_buf += remainder
        asyncio.run(client.try_parse_commands())

        self.assertEqual(client.GlobalData.sock_buf, b"")
        self.assertEqual(self.recorded_calls, ["open_sdwdate_log"])


class TorStatusReportingTests(unittest.TestCase):
    """Tests covering the client's Tor status reporting logic."""

    def setUp(self) -> None:
        self._orig_anon_installed = client.GlobalData.anon_connection_wizard_installed
        self._orig_tor_status = getattr(client, "tor_status", None)
        self._orig_set_tor_status = client.set_tor_status
        self.reported_statuses: list[str] = []

        async def record_status(status: str) -> None:
            self.reported_statuses.append(status)

        client.set_tor_status = record_status

    def tearDown(self) -> None:
        client.GlobalData.anon_connection_wizard_installed = self._orig_anon_installed
        if self._orig_tor_status is None:
            if hasattr(client, "tor_status"):
                delattr(client, "tor_status")
        else:
            client.tor_status = self._orig_tor_status
        client.set_tor_status = self._orig_set_tor_status

    def test_disabled_service_running_reports_disabled_running(self) -> None:
        client.GlobalData.anon_connection_wizard_installed = True
        client.tor_status = types.SimpleNamespace(tor_status=lambda: "tor_disabled")

        with mock.patch.object(client.os.path, "exists", return_value=True):
            asyncio.run(client.tor_status_changed())

        self.assertEqual(self.reported_statuses, ["disabled_running"])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
