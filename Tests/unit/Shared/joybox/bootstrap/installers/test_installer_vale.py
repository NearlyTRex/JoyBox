# Local imports
import joybox.bootstrap.constants as constants
import joybox.bootstrap.installers as installers
from fakes import RecordingConnection


###########################################################
# Vale
###########################################################

def make(**kwargs):
    connection = RecordingConnection(**kwargs)
    return installers.Vale(connection), connection


def test_only_local_ubuntu_is_supported(isolated_settings):
    vale, _ = make()
    assert vale.get_supported_environments() == [constants.EnvironmentType.LOCAL_UBUNTU]


def test_status_follows_the_binary(isolated_settings):
    vale, connection = make()
    assert not vale.is_installed()
    assert vale.get_package_status() == {"installed": [], "missing": ["vale"]}

    connection.existing_paths.add(vale.vale_binary_path)
    assert vale.get_package_status() == {"installed": ["vale"], "missing": []}


def test_the_release_url_is_pinned(isolated_settings):
    vale, _ = make()
    assert vale.get_release_url().endswith(f"/v{vale.vale_version}/vale_{vale.vale_version}_Linux_64-bit.tar.gz")


def test_install_places_an_executable_binary_and_cleans_up(isolated_settings):
    vale, connection = make()

    assert vale.install()
    assert connection.downloads == [(vale.get_release_url(), "/tmp/vale.tar.gz")]
    assert connection.ran("-xzf /tmp/vale.tar.gz -C /tmp/vale_extract")
    assert connection.moved == [("/tmp/vale_extract/vale", vale.vale_binary_path)]
    assert (vale.vale_binary_path, "755") in connection.permissions
    assert connection.removed_paths == ["/tmp/vale.tar.gz", "/tmp/vale_extract"]


def test_a_failed_extract_fails_the_install(isolated_settings):
    vale, connection = make(return_codes = {"-xzf": 1})

    assert not vale.install()
    assert connection.moved == []
    assert connection.removed_paths == ["/tmp/vale.tar.gz", "/tmp/vale_extract"]


def test_install_fails_when_no_binary_appears(isolated_settings, monkeypatch):
    vale, connection = make()
    monkeypatch.setattr(connection, "move_file_or_directory", lambda src, dest, sudo = False: True)

    assert not vale.install()


def test_uninstall_removes_a_present_binary(isolated_settings):
    vale, connection = make()
    connection.existing_paths.add(vale.vale_binary_path)
    assert vale.uninstall()
    assert connection.removed_paths == [vale.vale_binary_path]

    vale, connection = make()
    assert vale.uninstall()
    assert connection.removed_paths == []
