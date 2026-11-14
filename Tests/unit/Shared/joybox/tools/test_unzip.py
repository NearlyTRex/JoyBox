# Local imports
from joybox.tools import unzip
from tools_helpers import assert_installs_nothing


def test_the_program_is_the_exe_in_the_install_dir(isolated_settings):
    isolated_settings.set_value("Tools.Unzip", "unzip_exe", "unzip")
    isolated_settings.set_value("Tools.Unzip", "unzip_install_dir", "/opt/unzip/bin")

    tool = unzip.Unzip()

    assert tool.get_name() == "Unzip"
    assert tool.get_config() == {"Unzip": {"program": "/opt/unzip/bin/unzip"}}


def test_variables_in_the_install_dir_are_expanded(isolated_settings, monkeypatch):
    monkeypatch.setenv("JOYBOX_TEST_ROOT", "/srv/tools")
    isolated_settings.set_value("Tools.Unzip", "unzip_exe", "unzip")
    isolated_settings.set_value("Tools.Unzip", "unzip_install_dir", "$JOYBOX_TEST_ROOT/unzip")

    assert unzip.Unzip().get_config()["Unzip"]["program"] == "/srv/tools/unzip/unzip"


def test_setup_installs_nothing(steps):
    assert_installs_nothing(steps, unzip.Unzip())
