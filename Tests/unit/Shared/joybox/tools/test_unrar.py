# Local imports
from joybox.tools import unrar
from tools_helpers import assert_installs_nothing


def test_the_program_is_the_exe_in_the_install_dir(isolated_settings):
    isolated_settings.set_value("Tools.Unrar", "unrar_exe", "unrar")
    isolated_settings.set_value("Tools.Unrar", "unrar_install_dir", "/opt/unrar/bin")

    tool = unrar.Unrar()

    assert tool.get_name() == "Unrar"
    assert tool.get_config() == {"Unrar": {"program": "/opt/unrar/bin/unrar"}}


def test_variables_in_the_install_dir_are_expanded(isolated_settings, monkeypatch):
    monkeypatch.setenv("JOYBOX_TEST_ROOT", "/srv/tools")
    isolated_settings.set_value("Tools.Unrar", "unrar_exe", "unrar")
    isolated_settings.set_value("Tools.Unrar", "unrar_install_dir", "$JOYBOX_TEST_ROOT/unrar")

    assert unrar.Unrar().get_config()["Unrar"]["program"] == "/srv/tools/unrar/unrar"


def test_setup_installs_nothing(steps):
    assert_installs_nothing(steps, unrar.Unrar())
