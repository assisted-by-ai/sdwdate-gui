"""Tests for sdwdate status change handling."""

from __future__ import annotations

import json
import os
import tempfile
from unittest import IsolatedAsyncioTestCase
from unittest.mock import AsyncMock, patch

from sdwdate_gui import sdwdate_gui_client as client


class SdwdateStatusChangedTests(IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self._orig_status_path = client.GlobalData.sdwdate_status_path
        self._tmpdir = tempfile.TemporaryDirectory()
        client.GlobalData.sdwdate_status_path = os.path.join(
            self._tmpdir.name, "status.json"
        )

    async def asyncTearDown(self) -> None:
        client.GlobalData.sdwdate_status_path = self._orig_status_path
        self._tmpdir.cleanup()

    def _write_status(self, data: dict[str, object]) -> None:
        with open(client.GlobalData.sdwdate_status_path, "w", encoding="utf-8") as f:
            json.dump(data, f)

    async def test_missing_message_key_is_ignored(self) -> None:
        self._write_status({"icon": "success"})

        with patch.object(client, "set_sdwdate_status", AsyncMock()) as mock_set:
            await client.sdwdate_status_changed()

        mock_set.assert_not_awaited()

    async def test_non_string_message_is_rejected(self) -> None:
        self._write_status({"icon": "success", "message": 1})

        with patch.object(client, "set_sdwdate_status", AsyncMock()) as mock_set:
            await client.sdwdate_status_changed()

        mock_set.assert_not_awaited()
