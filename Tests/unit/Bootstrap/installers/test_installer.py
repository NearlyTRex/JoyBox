# Imports
import pytest

# Local imports
import constants
from installers import installer
from joybox import runoptions
from fakes import RecordingConnection


###########################################################
# Installer base
#
# compose_down and retire_app_dir are the two places where a missing guard
# destroys data the user expected to keep.
###########################################################

REMOTE_HOME = "/home/deploy"


def build(purge_data = False, app_name = "testapp"):
    connection = RecordingConnection(command_output = {"printf": REMOTE_HOME})
    base = installer.Installer(connection, runoptions.RunFlags(verbose = False, purge_data = purge_data))
    base.app_name = app_name
    return base, connection


###########################################################
# Remote home
###########################################################

def test_the_remote_home_is_resolved():
    base, _ = build()
    assert base.get_remote_home() == REMOTE_HOME


def test_the_remote_home_is_resolved_once():
    # Every app directory lookup would otherwise cost a round trip.
    base, connection = build()
    base.get_remote_home()
    base.get_remote_home()

    assert len([c for c in connection.command_strings() if "printf" in c]) == 1


def test_an_unresolvable_home_falls_back():
    connection = RecordingConnection(command_output = {"printf": ""})
    base = installer.Installer(connection, runoptions.RunFlags(verbose = False))
    base.app_name = "testapp"

    assert base.get_remote_home() == "$HOME"


def test_the_app_directory_is_built_from_the_home():
    base, _ = build(app_name = "filebrowser")
    assert base.get_app_dir() == f"{REMOTE_HOME}/apps/filebrowser"


###########################################################
# Environment support
###########################################################

def test_every_environment_is_supported_by_default():
    base, _ = build()

    for environment in constants.EnvironmentType:
        assert base.supports_environment(environment) is True


def test_an_unsupported_environment_is_rejected():
    base, _ = build()
    base.get_supported_environments = lambda: [constants.EnvironmentType.REMOTE_UBUNTU]

    assert base.supports_environment(constants.EnvironmentType.REMOTE_UBUNTU) is True
    assert base.supports_environment(constants.EnvironmentType.LOCAL_WINDOWS) is False


###########################################################
# Composing down
###########################################################

def test_volumes_are_kept_by_default():
    # "down -v" destroys databases and app data.
    base, connection = build(purge_data = False)
    base.compose_down()

    assert connection.ran("down")
    assert not connection.ran("down", "-v")


def test_volumes_are_removed_only_with_purge_data():
    base, connection = build(purge_data = True)
    base.compose_down()

    assert connection.ran("down", "-v")


def test_compose_runs_in_the_app_directory():
    base, connection = build()
    base.compose_down()

    directories = [call[1][0] for call in connection.called("set_current_working_directory")]
    assert f"{REMOTE_HOME}/apps/testapp" in directories


def test_the_working_directory_is_reset_afterwards():
    # A leaked cwd would silently redirect every later command.
    base, connection = build()
    base.compose_down()

    directories = [call[1][0] for call in connection.called("set_current_working_directory")]
    assert directories[-1] is None


def test_compose_down_uses_the_app_env_file():
    base, connection = build()
    base.compose_down()

    assert connection.ran("--env-file", f"{REMOTE_HOME}/apps/testapp/.env")


###########################################################
# Retiring the app directory
###########################################################

def test_the_app_directory_is_renamed_by_default():
    # Bind-mounted app data lives here, so removing it destroys data even when
    # the volumes were kept.
    base, connection = build(purge_data = False)
    base.retire_app_dir()

    assert connection.removed_paths == []
    assert len(connection.moved) == 1

    source, destination = connection.moved[0]
    assert source == f"{REMOTE_HOME}/apps/testapp"
    assert destination.startswith(f"{REMOTE_HOME}/apps/testapp.removed-")


def test_the_app_directory_is_removed_only_with_purge_data():
    base, connection = build(purge_data = True)
    base.retire_app_dir()

    assert connection.removed_paths == [f"{REMOTE_HOME}/apps/testapp"]
    assert connection.moved == []


def test_the_retired_directory_name_is_timestamped():
    base, connection = build()
    base.retire_app_dir()

    _, destination = connection.moved[0]
    stamp = destination.rsplit(".removed-", 1)[1]

    assert len(stamp) == 15 and stamp[8] == "_"


###########################################################
# Nginx snippets
###########################################################

def test_a_snippet_is_staged_installed_and_cleaned_up():
    base, connection = build()
    base.install_nginx_snippet("apex-root.conf", "location / { return 404; }")

    assert connection.written("/tmp/apex-root.conf") == "location / { return 404; }"
    assert connection.ran("install_snippet", "/tmp/apex-root.conf")
    assert "/tmp/apex-root.conf" in connection.removed_paths


###########################################################
# Abstract defaults
###########################################################

def test_the_base_reports_nothing_installed():
    base, _ = build()

    assert base.is_installed() is False
    assert base.get_package_status() is None


def test_the_base_does_not_claim_a_successful_action():
    # A subclass that forgets to override must not report success.
    base, _ = build()

    assert base.install() is False
    assert base.uninstall() is False
