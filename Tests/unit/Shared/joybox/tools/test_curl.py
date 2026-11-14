# Local imports
from joybox.tools import curl
from tools_helpers import assert_installs_nothing


def test_the_program_is_the_exe_in_the_install_dir(isolated_settings):
    isolated_settings.set_value("Tools.Curl", "curl_exe", "curl")
    isolated_settings.set_value("Tools.Curl", "curl_install_dir", "/opt/curl/bin")

    tool = curl.Curl()

    assert tool.get_name() == "Curl"
    assert tool.get_config() == {"Curl": {"program": "/opt/curl/bin/curl"}}


def test_variables_in_the_install_dir_are_expanded(isolated_settings, monkeypatch):
    monkeypatch.setenv("JOYBOX_TEST_ROOT", "/srv/tools")
    isolated_settings.set_value("Tools.Curl", "curl_exe", "curl")
    isolated_settings.set_value("Tools.Curl", "curl_install_dir", "$JOYBOX_TEST_ROOT/curl")

    assert curl.Curl().get_config()["Curl"]["program"] == "/srv/tools/curl/curl"


def test_setup_installs_nothing(steps):
    assert_installs_nothing(steps, curl.Curl())
