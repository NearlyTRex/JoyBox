# Third-party imports
import pytest

# Local imports
import joybox.bootstrap.constants as constants
from joybox.bootstrap.environments import env_remote_ubuntu
from joybox import runoptions
from fakes import RecordingConnection
from fakes import RecordingAptGet
from fakes import RecordingInstaller


###########################################################
# Remote Ubuntu
#
# Server components depend on each other (nginx before certbot before the
# apps), so the first failure stops the run.
###########################################################

def build(autoremove = False, aptget_results = None, installed = False, extra = None):
    environment = env_remote_ubuntu.RemoteUbuntu(
        ssh_host = "server.test",
        flags = runoptions.RunFlags(verbose = False, autoremove = autoremove, exit_on_failure = False))
    environment.connection = RecordingConnection()
    aptget = RecordingAptGet("aptget", installed = installed, results = aptget_results)
    environment.available_components = {"aptget": aptget, **(extra or {})}
    environment.installer_aptget = aptget
    return environment, aptget


def test_building_marks_the_environment_remote_ubuntu(isolated_settings):
    environment, _ = build()
    assert environment.get_environment_type() == constants.EnvironmentType.REMOTE_UBUNTU


def test_setup_refreshes_package_lists_before_installing(isolated_settings):
    environment, aptget = build()

    assert environment.setup()
    assert aptget.calls == ["update_package_lists", "install"]


def test_setup_stops_at_the_first_failure_even_without_exit_on_failure(isolated_settings):
    later = RecordingInstaller("certbot")
    environment, _ = build(aptget_results = {"install": False}, extra = {"certbot": later})

    assert environment.setup() is False
    assert later.calls == []


def test_a_deselected_aptget_skips_the_refresh(isolated_settings):
    environment, aptget = build()
    environment.set_components_to_process([])

    assert environment.setup()
    assert aptget.calls == []


@pytest.mark.parametrize("action", ["setup", "teardown"])
def test_autoremove_runs_after_a_clean_pass(isolated_settings, action):
    environment, aptget = build(autoremove = True, installed = action == "teardown")

    assert getattr(environment, action)()
    assert aptget.calls[-1] == "auto_remove_packages"


@pytest.mark.parametrize("action", ["setup", "teardown"])
def test_a_failed_autoremove_fails_the_run(isolated_settings, action):
    environment, _ = build(autoremove = True, installed = action == "teardown",
        aptget_results = {"auto_remove_packages": False})

    assert getattr(environment, action)() is False


def test_teardown_without_autoremove_only_uninstalls(isolated_settings):
    environment, aptget = build(installed = True)

    assert environment.teardown()
    assert aptget.calls == ["uninstall"]
