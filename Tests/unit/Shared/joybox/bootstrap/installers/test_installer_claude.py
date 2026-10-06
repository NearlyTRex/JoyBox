# Imports
import os

# Third-party imports
import pytest

# Local imports
import joybox.bootstrap.constants as constants
import joybox.bootstrap.installers as installers
from fakes import RecordingConnection


###########################################################
# Claude Code CLI
#
# The upstream script has installed to three places over time; any of them
# counts as installed, and uninstall clears all of them.
###########################################################

def make(**kwargs):
    connection = RecordingConnection(**kwargs)
    return installers.Claude(connection), connection


def binary_paths(claude):
    return [claude.claude_binary_path, claude.claude_local_bin_path, claude.claude_home_binary_path]


def test_only_local_ubuntu_is_supported(isolated_settings):
    claude, _ = make()
    assert claude.get_supported_environments() == [constants.EnvironmentType.LOCAL_UBUNTU]


def test_nothing_present_is_not_installed(isolated_settings):
    claude, _ = make()
    assert not claude.is_installed()
    assert claude.get_package_status() == {"installed": [], "missing": ["claude-code"]}


@pytest.mark.parametrize("index", [0, 1, 2])
def test_any_install_location_counts(isolated_settings, index):
    claude, connection = make()
    connection.existing_paths.add(binary_paths(claude)[index])

    assert claude.is_installed()
    assert claude.get_package_status() == {"installed": ["claude-code"], "missing": []}


def test_install_runs_the_upstream_script_and_removes_it(isolated_settings):
    claude, connection = make()
    connection.existing_paths.add(claude.claude_local_bin_path)

    assert claude.install()
    assert connection.downloads == [("https://claude.ai/install.sh", "/tmp/claude_install.sh")]
    assert connection.ran("bash /tmp/claude_install.sh")
    assert connection.removed_paths == ["/tmp/claude_install.sh"]


def test_a_failed_script_fails_the_install_and_still_cleans_up(isolated_settings):
    claude, connection = make(return_codes = {"claude_install.sh": 1})

    assert not claude.install()
    assert connection.removed_paths == ["/tmp/claude_install.sh"]


def test_install_fails_when_no_binary_appears(isolated_settings):
    claude, _ = make()
    assert not claude.install()


def test_uninstall_removes_every_location(isolated_settings):
    claude, connection = make()
    local_dir = os.path.expanduser("~/.claude/local")
    connection.existing_paths.update([claude.claude_binary_path, claude.claude_local_bin_path, local_dir])

    assert claude.uninstall()
    assert connection.removed_paths == [claude.claude_binary_path, claude.claude_local_bin_path, local_dir]
    assert connection.called("remove_file_or_directory")[0][2] == {"sudo": True}


def test_uninstall_of_nothing_succeeds(isolated_settings):
    claude, connection = make()

    assert claude.uninstall()
    assert connection.removed_paths == []
