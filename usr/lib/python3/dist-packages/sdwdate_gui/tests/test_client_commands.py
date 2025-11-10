"""Tests for sdwdate_gui_client command parsing."""

from __future__ import annotations

from unittest import IsolatedAsyncioTestCase
from unittest.mock import AsyncMock, patch

import sys
from types import SimpleNamespace


if "pyinotify" not in sys.modules:
    class _DummyProcessEvent:  # pragma: no cover - attribute-less stub
        pass

    sys.modules["pyinotify"] = SimpleNamespace(
        ProcessEvent=_DummyProcessEvent,
        Event=SimpleNamespace,
        AsyncioNotifier=object,
        WatchManager=object,
    )

from sdwdate_gui import sdwdate_gui_client as client


class TryParseCommandsTests(IsolatedAsyncioTestCase):
    async def asyncTearDown(self) -> None:
        client.GlobalData.sock_buf = b""

    async def test_unknown_command_disconnects(self) -> None:
        msg = b"unknown"
        client.GlobalData.sock_buf = len(msg).to_bytes(2, "big") + msg

        with patch.object(client, "kick_server", AsyncMock()) as mock_kick_server:
            await client.try_parse_commands()

        mock_kick_server.assert_awaited_once()
        self.assertEqual(client.GlobalData.sock_buf, b"")
