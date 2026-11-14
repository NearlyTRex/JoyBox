# Local imports
from joybox.tools import steamcmd
from tools_helpers import assert_installs_nothing


def test_the_program_is_the_exe_in_the_install_dir(isolated_settings):
    isolated_settings.set_value("Tools.Steam", "steamcmd_exe", "steamcmd")
    isolated_settings.set_value("Tools.Steam", "steamcmd_install_dir", "/opt/steamcmd/bin")

    tool = steamcmd.SteamCMD()

    assert tool.get_name() == "SteamCMD"
    assert tool.get_config() == {"SteamCMD": {"program": "/opt/steamcmd/bin/steamcmd"}}


def test_variables_in_the_install_dir_are_expanded(isolated_settings, monkeypatch):
    monkeypatch.setenv("JOYBOX_TEST_ROOT", "/srv/tools")
    isolated_settings.set_value("Tools.Steam", "steamcmd_exe", "steamcmd")
    isolated_settings.set_value("Tools.Steam", "steamcmd_install_dir", "$JOYBOX_TEST_ROOT/steamcmd")

    assert steamcmd.SteamCMD().get_config()["SteamCMD"]["program"] == "/srv/tools/steamcmd/steamcmd"


def test_setup_installs_nothing(steps):
    assert_installs_nothing(steps, steamcmd.SteamCMD())
