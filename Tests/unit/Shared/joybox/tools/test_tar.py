# Local imports
from joybox.tools import tar
from tools_helpers import assert_installs_nothing


def test_the_program_is_the_exe_in_the_install_dir(isolated_settings):
    isolated_settings.set_value("Tools.Tar", "tar_exe", "tar")
    isolated_settings.set_value("Tools.Tar", "tar_install_dir", "/opt/tar/bin")

    tool = tar.Tar()

    assert tool.get_name() == "Tar"
    assert tool.get_config() == {"Tar": {"program": "/opt/tar/bin/tar"}}


def test_variables_in_the_install_dir_are_expanded(isolated_settings, monkeypatch):
    monkeypatch.setenv("JOYBOX_TEST_ROOT", "/srv/tools")
    isolated_settings.set_value("Tools.Tar", "tar_exe", "tar")
    isolated_settings.set_value("Tools.Tar", "tar_install_dir", "$JOYBOX_TEST_ROOT/tar")

    assert tar.Tar().get_config()["Tar"]["program"] == "/srv/tools/tar/tar"


def test_setup_installs_nothing(steps):
    assert_installs_nothing(steps, tar.Tar())
