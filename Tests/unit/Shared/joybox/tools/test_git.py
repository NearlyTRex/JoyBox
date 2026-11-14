# Local imports
from joybox.tools import git
from tools_helpers import assert_installs_nothing


def test_the_program_is_the_exe_in_the_install_dir(isolated_settings):
    isolated_settings.set_value("Tools.Git", "git_exe", "git")
    isolated_settings.set_value("Tools.Git", "git_install_dir", "/opt/git/bin")

    tool = git.Git()

    assert tool.get_name() == "Git"
    assert tool.get_config() == {"Git": {"program": "/opt/git/bin/git"}}


def test_variables_in_the_install_dir_are_expanded(isolated_settings, monkeypatch):
    monkeypatch.setenv("JOYBOX_TEST_ROOT", "/srv/tools")
    isolated_settings.set_value("Tools.Git", "git_exe", "git")
    isolated_settings.set_value("Tools.Git", "git_install_dir", "$JOYBOX_TEST_ROOT/git")

    assert git.Git().get_config()["Git"]["program"] == "/srv/tools/git/git"


def test_setup_installs_nothing(steps):
    assert_installs_nothing(steps, git.Git())
