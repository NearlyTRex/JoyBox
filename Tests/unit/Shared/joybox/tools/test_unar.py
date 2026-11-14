# Local imports
from joybox.tools import unar
from tools_helpers import assert_installs_nothing


def test_the_program_is_the_exe_in_the_install_dir(isolated_settings):
    isolated_settings.set_value("Tools.Unar", "unar_exe", "unar")
    isolated_settings.set_value("Tools.Unar", "unar_install_dir", "/opt/unar/bin")

    tool = unar.Unar()

    assert tool.get_name() == "Unar"
    assert tool.get_config() == {"Unar": {"program": "/opt/unar/bin/unar"}}


def test_variables_in_the_install_dir_are_expanded(isolated_settings, monkeypatch):
    monkeypatch.setenv("JOYBOX_TEST_ROOT", "/srv/tools")
    isolated_settings.set_value("Tools.Unar", "unar_exe", "unar")
    isolated_settings.set_value("Tools.Unar", "unar_install_dir", "$JOYBOX_TEST_ROOT/unar")

    assert unar.Unar().get_config()["Unar"]["program"] == "/srv/tools/unar/unar"


def test_setup_installs_nothing(steps):
    assert_installs_nothing(steps, unar.Unar())
