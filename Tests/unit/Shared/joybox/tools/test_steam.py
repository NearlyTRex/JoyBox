# Local imports
from joybox.tools import steam
from tools_helpers import assert_installs_nothing


def test_the_program_is_the_exe_in_the_install_dir(isolated_settings):
    isolated_settings.set_value("Tools.Steam", "steam_exe", "steam")
    isolated_settings.set_value("Tools.Steam", "steam_install_dir", "/opt/steam/bin")

    tool = steam.Steam()

    assert tool.get_name() == "Steam"
    assert tool.get_config() == {"Steam": {"program": "/opt/steam/bin/steam"}}


def test_variables_in_the_install_dir_are_expanded(isolated_settings, monkeypatch):
    monkeypatch.setenv("JOYBOX_TEST_ROOT", "/srv/tools")
    isolated_settings.set_value("Tools.Steam", "steam_exe", "steam")
    isolated_settings.set_value("Tools.Steam", "steam_install_dir", "$JOYBOX_TEST_ROOT/steam")

    assert steam.Steam().get_config()["Steam"]["program"] == "/srv/tools/steam/steam"


def test_setup_installs_nothing(steps):
    assert_installs_nothing(steps, steam.Steam())
