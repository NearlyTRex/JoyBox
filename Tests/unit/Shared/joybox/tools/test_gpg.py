# Local imports
from joybox.tools import gpg
from tools_helpers import assert_installs_nothing


def test_the_program_is_the_exe_in_the_install_dir(isolated_settings):
    isolated_settings.set_value("Tools.Gpg", "gpg_exe", "gpg")
    isolated_settings.set_value("Tools.Gpg", "gpg_install_dir", "/opt/gpg/bin")

    tool = gpg.Gpg()

    assert tool.get_name() == "Gpg"
    assert tool.get_config() == {"Gpg": {"program": "/opt/gpg/bin/gpg"}}


def test_variables_in_the_install_dir_are_expanded(isolated_settings, monkeypatch):
    monkeypatch.setenv("JOYBOX_TEST_ROOT", "/srv/tools")
    isolated_settings.set_value("Tools.Gpg", "gpg_exe", "gpg")
    isolated_settings.set_value("Tools.Gpg", "gpg_install_dir", "$JOYBOX_TEST_ROOT/gpg")

    assert gpg.Gpg().get_config()["Gpg"]["program"] == "/srv/tools/gpg/gpg"


def test_setup_installs_nothing(steps):
    assert_installs_nothing(steps, gpg.Gpg())
