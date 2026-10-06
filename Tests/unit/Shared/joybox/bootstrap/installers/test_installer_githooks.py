# Local imports
import joybox.bootstrap.constants as constants
import joybox.bootstrap.installers as installers
from joybox import runoptions
from fakes import RecordingConnection


###########################################################
# Git hooks
#
# core.hooksPath lives in .git/config, which is not cloned, so every checkout
# has to be pointed at the version-controlled hooks once.
###########################################################

GET_COMMAND = "config --local --get core.hooksPath"


def make(hooks_path = "", pretend_run = False, **kwargs):
    connection = RecordingConnection(command_output = {GET_COMMAND: hooks_path}, **kwargs)
    flags = runoptions.RunFlags(verbose = False, pretend_run = pretend_run)
    hooks = installers.GitHooks(connection, flags)
    return hooks, connection


def test_only_local_ubuntu_is_supported(isolated_settings):
    hooks, _ = make()
    assert hooks.get_supported_environments() == [constants.EnvironmentType.LOCAL_UBUNTU]


def test_status_follows_the_git_setting(isolated_settings):
    hooks, _ = make()
    assert not hooks.is_installed()
    assert hooks.get_package_status() == {"installed": [], "missing": ["core.hooksPath"]}

    hooks, _ = make(hooks_path = ".githooks\n")
    assert hooks.is_installed()
    assert hooks.get_package_status() == {"installed": ["core.hooksPath"], "missing": []}


def test_another_hooks_path_is_not_installed(isolated_settings):
    hooks, _ = make(hooks_path = "hooks")
    assert not hooks.is_installed()


def test_install_points_git_at_the_repo_hooks(isolated_settings):
    hooks, connection = make(hooks_path = ".githooks")
    connection.existing_paths.add(hooks.hooks_dir)

    assert hooks.install()
    assert connection.ran("-C", hooks.joybox_root, "config core.hooksPath .githooks")


def test_install_needs_the_hooks_directory(isolated_settings):
    hooks, connection = make()

    assert not hooks.install()
    assert not connection.ran("config core.hooksPath")


def test_install_fails_when_the_setting_does_not_stick(isolated_settings):
    hooks, connection = make()
    connection.existing_paths.add(hooks.hooks_dir)

    assert not hooks.install()


def test_a_pretend_run_skips_the_verification(isolated_settings):
    hooks, connection = make(pretend_run = True)
    connection.existing_paths.add(hooks.hooks_dir)

    assert hooks.install()


def test_uninstall_unsets_a_present_setting(isolated_settings):
    hooks, connection = make(hooks_path = ".githooks")
    assert hooks.uninstall()
    assert connection.ran("config --unset core.hooksPath")

    hooks, connection = make()
    assert hooks.uninstall()
    assert not connection.ran("--unset")
