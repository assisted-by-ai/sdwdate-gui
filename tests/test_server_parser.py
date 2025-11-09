import sys
from pathlib import Path
import unittest

TEST_DIR = Path(__file__).resolve().parent
if str(TEST_DIR) not in sys.path:
    sys.path.insert(0, str(TEST_DIR))

from qt5_shims import add_dist_packages_to_path, ensure_pyqt5

ensure_pyqt5()
add_dist_packages_to_path()
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
