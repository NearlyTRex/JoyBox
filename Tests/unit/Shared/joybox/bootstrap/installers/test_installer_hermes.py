# Imports
import os

# Third-party imports
import pytest

# Local imports
import joybox.bootstrap.constants as constants
import joybox.bootstrap.installers as installers
from fakes import RecordingConnection


###########################################################
# Hermes Agent
#
# Upstream builds no wheels, so it runs from a checkout of a pinned release
# with an editable install. Its own installer edits shell rc files, so the
# pinned tag, the venv and the one link are all this one is allowed to touch.
###########################################################

def make(**kwargs):
    connection = RecordingConnection(**kwargs)
    return installers.HermesAgent(connection), connection


def installed_paths(hermes):
    return [hermes.command_path]


def test_only_local_ubuntu_is_supported(isolated_settings):
    hermes, _ = make()
    assert hermes.get_supported_environments() == [constants.EnvironmentType.LOCAL_UBUNTU]


def test_the_release_and_location_come_from_the_settings(isolated_settings):
    hermes, _ = make()
    assert hermes.release.startswith("v")
    assert hermes.source_dir == os.path.join(hermes.install_dir, "src")
    assert "$" not in hermes.install_dir


def test_status_follows_the_venv_command(isolated_settings):
    hermes, connection = make()
    assert not hermes.is_installed()
    assert hermes.get_package_status() == {"installed": [], "missing": ["hermes-agent"]}

    connection.existing_paths.add(hermes.command_path)
    assert hermes.is_installed()
    assert hermes.get_package_status() == {"installed": ["hermes-agent"], "missing": []}


###########################################################
# Install
###########################################################

def test_fresh_install_clones_the_release_and_installs_it_editable(isolated_settings):
    hermes, connection = make()
    connection.existing_paths.update(installed_paths(hermes))

    assert hermes.install()
    assert connection.ran("clone --depth 1 --branch", hermes.release, hermes.repository_url, hermes.source_dir)
    assert connection.ran("-m venv", hermes.venv_dir)
    assert connection.ran(os.path.join(hermes.venv_dir, "bin", "pip"), "install --upgrade --editable", hermes.source_dir)
    assert connection.called("link_file_or_directory")[0][1] == (hermes.command_path, hermes.link_path)


def test_nothing_runs_as_root_or_through_the_upstream_installer(isolated_settings):
    # Its install.sh edits shell rc files and apt-installs packages.
    hermes, connection = make()
    connection.existing_paths.update(installed_paths(hermes))

    hermes.install()

    assert not any(call[2].get("sudo") for call in connection.calls)
    assert not connection.ran_any("install.sh", "setup-hermes")


def test_an_existing_checkout_moves_to_the_release(isolated_settings):
    hermes, connection = make()
    connection.existing_paths.update(installed_paths(hermes) + [
        os.path.join(hermes.source_dir, ".git"), hermes.venv_dir])

    assert hermes.install()
    assert connection.ran("fetch --depth 1 origin", f"refs/tags/{hermes.release}")
    assert connection.ran("checkout --detach", hermes.release)
    assert not connection.ran("clone")
    assert not connection.ran("-m venv")


@pytest.mark.parametrize("fragment", ["clone --depth", "-m venv", "--editable"])
def test_a_failing_step_stops_the_install(isolated_settings, fragment):
    hermes, connection = make(return_codes = {fragment: 1})
    connection.existing_paths.update(installed_paths(hermes))

    assert not hermes.install()
    assert not connection.called("link_file_or_directory")


def test_a_failed_fetch_of_an_existing_checkout_stops_the_install(isolated_settings):
    hermes, connection = make(return_codes = {"fetch --depth": 1})
    connection.existing_paths.add(os.path.join(hermes.source_dir, ".git"))

    assert not hermes.install()
    assert not connection.ran("checkout")


def test_install_fails_when_the_command_is_absent(isolated_settings):
    hermes, connection = make()

    assert not hermes.install()
    assert not connection.called("link_file_or_directory")


###########################################################
# Uninstall
###########################################################

def test_uninstall_removes_the_link_and_the_install_but_not_the_data(isolated_settings):
    hermes, connection = make()
    connection.existing_paths.update({hermes.link_path, hermes.install_dir})

    assert hermes.uninstall()
    assert connection.removed_paths == [hermes.link_path, hermes.install_dir]
    assert not any(".hermes" in path for path in connection.removed_paths)


def test_uninstall_of_nothing_succeeds(isolated_settings):
    hermes, connection = make()

    assert hermes.uninstall()
    assert connection.removed_paths == []


def test_a_failed_link_fails_the_install(isolated_settings, monkeypatch):
    hermes, connection = make()
    connection.existing_paths.update(installed_paths(hermes))
    monkeypatch.setattr(connection, "link_file_or_directory", lambda src, dest, sudo = False: False)

    assert not hermes.install()


def test_an_unremovable_install_fails_the_uninstall(isolated_settings, monkeypatch):
    hermes, connection = make()
    connection.existing_paths.add(hermes.install_dir)
    monkeypatch.setattr(connection, "remove_file_or_directory", lambda src, sudo = False: False)

    assert not hermes.uninstall()
