# Third-party imports
import pytest

# Local imports
import joybox.bootstrap.constants as constants
from joybox.bootstrap.environments import env_local_ubuntu
from joybox import runoptions
from fakes import RecordingConnection
from fakes import RecordingAptGet


###########################################################
# Local Ubuntu
#
# Package lists refresh before anything installs, and autoremove is opt-in and
# runs only after a clean pass.
###########################################################

def build(autoremove = False, aptget_results = None, installed = False):
    environment = env_local_ubuntu.LocalUbuntu(
        flags = runoptions.RunFlags(verbose = False, autoremove = autoremove))
    environment.connection = RecordingConnection()
    aptget = RecordingAptGet("aptget", installed = installed, results = aptget_results)
    environment.available_components = {"aptget": aptget}
    environment.installer_aptget = aptget
    return environment, aptget


def test_building_marks_the_environment_local_ubuntu(isolated_settings):
    environment, _ = build()
    assert environment.get_environment_type() == constants.EnvironmentType.LOCAL_UBUNTU


def test_setup_refreshes_package_lists_before_installing(isolated_settings):
    environment, aptget = build()

    assert environment.setup()
    assert aptget.calls == ["update_package_lists", "install"]


def test_setup_leaves_packages_alone_without_autoremove(isolated_settings):
    environment, aptget = build()
    environment.setup()

    assert "auto_remove_packages" not in aptget.calls


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
