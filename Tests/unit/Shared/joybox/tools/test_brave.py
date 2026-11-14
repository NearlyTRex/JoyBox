# Local imports
from joybox.tools import brave
from tools_helpers import assert_installs_nothing


def test_the_program_and_download_dir_come_from_the_settings(isolated_settings):
    isolated_settings.set_value("Tools.Brave", "brave_exe", "brave")
    isolated_settings.set_value("Tools.Brave", "brave_install_dir", "/opt/brave")
    isolated_settings.set_value("Tools.Brave", "brave_download_dir", "/home/tester/Downloads")

    tool = brave.Brave()

    assert tool.get_name() == "Brave"
    assert tool.get_config() == {"Brave": {
        "program": "/opt/brave/brave",
        "download_dir": "/home/tester/Downloads",
    }}


def test_variables_in_both_dirs_are_expanded(isolated_settings, monkeypatch):
    monkeypatch.setenv("JOYBOX_TEST_ROOT", "/srv/tester")
    isolated_settings.set_value("Tools.Brave", "brave_exe", "brave")
    isolated_settings.set_value("Tools.Brave", "brave_install_dir", "$JOYBOX_TEST_ROOT/brave")
    isolated_settings.set_value("Tools.Brave", "brave_download_dir", "$JOYBOX_TEST_ROOT/Downloads")

    entry = brave.Brave().get_config()["Brave"]

    assert entry == {"program": "/srv/tester/brave/brave", "download_dir": "/srv/tester/Downloads"}


def test_setup_installs_nothing(steps):
    assert_installs_nothing(steps, brave.Brave())
