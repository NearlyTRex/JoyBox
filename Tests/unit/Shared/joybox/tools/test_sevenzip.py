# Local imports
from joybox.tools import sevenzip
from tools_helpers import assert_installs_nothing


def test_the_program_is_the_exe_in_the_install_dir(isolated_settings):
    isolated_settings.set_value("Tools.7Zip", "7z_exe", "7zz")
    isolated_settings.set_value("Tools.7Zip", "7z_install_dir", "/opt/sevenzip/bin")

    tool = sevenzip.SevenZip()

    assert tool.get_name() == "7-Zip"
    assert tool.get_config() == {"7-Zip": {"program": "/opt/sevenzip/bin/7zz"}}


def test_variables_in_the_install_dir_are_expanded(isolated_settings, monkeypatch):
    monkeypatch.setenv("JOYBOX_TEST_ROOT", "/srv/tools")
    isolated_settings.set_value("Tools.7Zip", "7z_exe", "7zz")
    isolated_settings.set_value("Tools.7Zip", "7z_install_dir", "$JOYBOX_TEST_ROOT/sevenzip")

    assert sevenzip.SevenZip().get_config()["7-Zip"]["program"] == "/srv/tools/sevenzip/7zz"


def test_setup_installs_nothing(steps):
    assert_installs_nothing(steps, sevenzip.SevenZip())
