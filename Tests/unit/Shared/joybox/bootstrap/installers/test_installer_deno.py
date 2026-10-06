# Local imports
import joybox.bootstrap.constants as constants
import joybox.bootstrap.installers as installers
from fakes import RecordingConnection


###########################################################
# Deno
###########################################################

def make(**kwargs):
    connection = RecordingConnection(**kwargs)
    return installers.Deno(connection), connection


def test_only_local_ubuntu_is_supported(isolated_settings):
    deno, _ = make()
    assert deno.get_supported_environments() == [constants.EnvironmentType.LOCAL_UBUNTU]


def test_status_follows_the_binary(isolated_settings):
    deno, connection = make()
    assert not deno.is_installed()
    assert deno.get_package_status() == {"installed": [], "missing": ["deno"]}

    connection.existing_paths.add(deno.deno_binary_path)
    assert deno.is_installed()
    assert deno.get_package_status() == {"installed": ["deno"], "missing": []}


def test_install_runs_the_upstream_script(isolated_settings):
    deno, connection = make()
    connection.existing_paths.add(deno.deno_binary_path)

    assert deno.install()
    assert connection.downloads == [("https://deno.land/install.sh", "/tmp/deno_install.sh")]
    assert connection.ran("sh /tmp/deno_install.sh")


def test_a_failed_script_fails_the_install(isolated_settings):
    deno, _ = make(return_codes = {"deno_install.sh": 1})
    assert not deno.install()


def test_install_fails_when_no_binary_appears(isolated_settings):
    deno, _ = make()
    assert not deno.install()


def test_uninstall_removes_the_directory(isolated_settings):
    deno, connection = make()
    connection.existing_paths.add(deno.deno_install_dir)

    assert deno.uninstall()
    assert connection.removed_paths == [deno.deno_install_dir]


def test_uninstall_of_nothing_succeeds(isolated_settings):
    deno, connection = make()

    assert deno.uninstall()
    assert connection.removed_paths == []
