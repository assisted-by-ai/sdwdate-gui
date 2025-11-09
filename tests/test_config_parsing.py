import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

TEST_DIR = Path(__file__).resolve().parent
if str(TEST_DIR) not in sys.path:
    sys.path.insert(0, str(TEST_DIR))

from qt5_shims import add_dist_packages_to_path, ensure_pyqt5

ensure_pyqt5()
add_dist_packages_to_path()

from sdwdate_gui import sdwdate_gui_client as client
from sdwdate_gui import sdwdate_gui_server as server


class ConfigParsingTests(unittest.TestCase):
    def _write_config(self, tmp_path: Path, content: str) -> Path:
        cfg_path = tmp_path / "sample.conf"
        cfg_path.write_text(content, encoding="utf-8")
        return cfg_path

    def test_client_disable_allows_inline_comment(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            cfg_path = self._write_config(
                Path(tmp_dir),
                "disable=true # keep disabled\n",
            )
            with mock.patch.object(client.sys, "exit", side_effect=SystemExit(0)):
                with self.assertRaises(SystemExit) as ctx:
                    client.parse_config_file(str(cfg_path))
        self.assertEqual(ctx.exception.code, 0)

    def test_server_disable_allows_inline_comment(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            cfg_path = self._write_config(
                Path(tmp_dir),
                "disable=true # keep disabled\n",
            )
            with mock.patch.object(server.sys, "exit", side_effect=SystemExit(0)):
                with self.assertRaises(SystemExit) as ctx:
                    server.parse_config_file(str(cfg_path))
        self.assertEqual(ctx.exception.code, 0)


if __name__ == "__main__":
    unittest.main()
