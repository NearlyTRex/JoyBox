# Local imports
from joybox.tools import chrome
from tools_helpers import assert_installs_nothing


def test_the_program_and_download_dir_come_from_the_settings(isolated_settings):
    isolated_settings.set_value("Tools.Chrome", "chrome_exe", "chrome")
    isolated_settings.set_value("Tools.Chrome", "chrome_install_dir", "/opt/chrome")
    isolated_settings.set_value("Tools.Chrome", "chrome_download_dir", "/home/tester/Downloads")

    tool = chrome.Chrome()

    assert tool.get_name() == "Chrome"
    assert tool.get_config() == {"Chrome": {
        "program": "/opt/chrome/chrome",
        "download_dir": "/home/tester/Downloads",
    }}


def test_variables_in_both_dirs_are_expanded(isolated_settings, monkeypatch):
    monkeypatch.setenv("JOYBOX_TEST_ROOT", "/srv/tester")
    isolated_settings.set_value("Tools.Chrome", "chrome_exe", "chrome")
    isolated_settings.set_value("Tools.Chrome", "chrome_install_dir", "$JOYBOX_TEST_ROOT/chrome")
    isolated_settings.set_value("Tools.Chrome", "chrome_download_dir", "$JOYBOX_TEST_ROOT/Downloads")

    entry = chrome.Chrome().get_config()["Chrome"]

    assert entry == {"program": "/srv/tester/chrome/chrome", "download_dir": "/srv/tester/Downloads"}


def test_setup_installs_nothing(steps):
    assert_installs_nothing(steps, chrome.Chrome())
