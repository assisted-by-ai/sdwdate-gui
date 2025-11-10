import os
import shutil
import tempfile
import unittest

from sdwdate_gui.sdwdate_gui_shared import ConfigData, parse_config_files


class ParseConfigFilesTest(unittest.TestCase):
    def setUp(self) -> None:
        self._orig_conf_dir_list = ConfigData.conf_dir_list.copy()
        self._tempdir = tempfile.mkdtemp()
        ConfigData.conf_dir_list = [self._tempdir]
        ConfigData.conf_dict = ConfigData.conf_defaults.copy()

    def tearDown(self) -> None:
        shutil.rmtree(self._tempdir)
        ConfigData.conf_dir_list = self._orig_conf_dir_list
        ConfigData.conf_dict = ConfigData.conf_defaults.copy()

    def _write_config(self, content: str, filename: str = "10-test.conf") -> str:
        path = os.path.join(self._tempdir, filename)
        with open(path, "w", encoding="utf-8") as config_file:
            config_file.write(content)
        return path

    def test_removed_config_resets_to_defaults(self) -> None:
        self._write_config("disable = true\n")

        parse_config_files()
        self.assertTrue(ConfigData.conf_dict["disable"])  # sanity check

        os.remove(os.path.join(self._tempdir, "10-test.conf"))

        parse_config_files()
        self.assertFalse(
            ConfigData.conf_dict["disable"],
            "Configuration defaults should be restored after config removal",
        )


if __name__ == "__main__":
    unittest.main()
