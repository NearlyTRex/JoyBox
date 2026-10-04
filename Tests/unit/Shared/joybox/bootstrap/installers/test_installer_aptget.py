# Local imports
import joybox.bootstrap.installers as installers
import joybox.bootstrap.constants as constants
from joybox.bootstrap.installers import installer_aptget
from fakes import RecordingConnection

INSTALLED = "Status: install ok installed"
AVAILABLE = "foo:\n  Installed: (none)\n  Candidate: 1.0-1\n"


def build(packages = None, return_codes = None, command_output = None):
    connection = RecordingConnection(return_codes = return_codes, command_output = command_output)
    aptget = installers.AptGet(connection)
    aptget.get_packages = lambda: list(packages or [])
    return aptget, connection


###########################################################
# Package descriptors
###########################################################

def test_string_package_is_its_own_id_and_name():
    assert installer_aptget.get_aptget_package_id("vim") == "vim"
    assert installer_aptget.get_aptget_package_info("vim") == {
        "id": "vim", "name": "vim", "description": "", "category": ""}


def test_dict_package_fields():
    pkg = {"id": "vim", "name": "Vim", "description": "editor", "category": "dev"}
    assert installer_aptget.get_aptget_package_id(pkg) == "vim"
    assert installer_aptget.get_aptget_package_info(pkg) == pkg


def test_dict_package_name_defaults_to_id():
    assert installer_aptget.get_aptget_package_id({}) == ""
    assert installer_aptget.get_aptget_package_info({"id": "vim"})["name"] == "vim"


def test_supported_environments_are_ubuntu(isolated_settings):
    aptget, _ = build()
    assert aptget.get_supported_environments() == [
        constants.EnvironmentType.LOCAL_UBUNTU, constants.EnvironmentType.REMOTE_UBUNTU]


def test_package_list_follows_environment_type(isolated_settings):
    aptget = installers.AptGet(RecordingConnection())
    assert isinstance(aptget.get_packages(), list)


###########################################################
# Install state
###########################################################

def test_installed_when_every_package_reports_installed(isolated_settings):
    aptget, _ = build(["vim", {"id": "git"}], command_output = {"-s": INSTALLED})
    assert aptget.is_installed()


def test_one_missing_package_is_not_installed(isolated_settings):
    aptget, _ = build(["vim"], command_output = {"-s": "Status: deinstall"})
    assert not aptget.is_installed()


def test_package_status_splits_installed_and_missing(isolated_settings):
    aptget, _ = build(
        ["vim", {"id": "git", "name": "Git"}],
        command_output = {"-s vim": INSTALLED})
    assert aptget.get_package_status() == {"installed": ["vim"], "missing": ["Git"]}


###########################################################
# Install
###########################################################

def test_install_runs_noninteractive_install(isolated_settings):
    aptget, connection = build(["vim"], command_output = {"policy": AVAILABLE})
    assert aptget.install()

    assert connection.ran("DEBIAN_FRONTEND=noninteractive", "install -y", "--force-confold", "vim")


def test_install_failure_stops(isolated_settings):
    aptget, connection = build(
        [{"id": "vim", "name": "Vim"}, "git"],
        command_output = {"policy": AVAILABLE},
        return_codes = {"install -y": 1})
    assert not aptget.install()

    assert not connection.ran("install -y", "git")


def test_package_without_candidate_is_skipped(isolated_settings):
    aptget, connection = build(["gone"], command_output = {"policy": "gone:\n  Candidate: (none)\n"})
    assert aptget.install_package("gone")

    assert not connection.ran("install -y")


def test_package_missing_from_policy_is_unavailable(isolated_settings):
    aptget, _ = build(command_output = {"policy": "N: Unable to locate package"})
    assert not aptget.is_package_available("gone")


def test_package_that_would_remove_others_is_skipped(isolated_settings):
    simulation = "Inst foo (1.0)\nRemv bar [2.0]\nRemv\nRemv baz [3.0]\n"
    aptget, connection = build(command_output = {"policy": AVAILABLE, "install -s": simulation})
    assert aptget.packages_removed_by_install("foo") == ["bar", "baz"]
    assert aptget.install_package("foo")

    assert not connection.ran("install -y")


###########################################################
# Foreign architectures
###########################################################

def test_no_foreign_packages_leaves_architectures_alone(isolated_settings):
    aptget, connection = build(["vim"])
    assert aptget.ensure_foreign_architectures()

    assert not connection.ran("--print-foreign-architectures")


def test_missing_architecture_is_added_and_lists_refreshed(isolated_settings):
    aptget, connection = build(["wine32:i386", "libc6:i386", "trailing:"])
    assert aptget.ensure_foreign_architectures()

    assert connection.ran("--add-architecture", "i386")
    assert len([c for c in connection.command_strings() if "--add-architecture" in c]) == 1
    assert connection.ran("update")


def test_enabled_architecture_is_not_re_added(isolated_settings):
    aptget, connection = build(
        ["wine32:i386"], command_output = {"--print-foreign-architectures": "i386\n"})
    assert aptget.ensure_foreign_architectures()

    assert not connection.ran("--add-architecture")
    assert not connection.ran("update")


def test_failure_to_add_architecture_fails_install(isolated_settings):
    aptget, connection = build(["wine32:i386"], return_codes = {"--add-architecture": 1})
    assert not aptget.install()

    assert not connection.ran("install -y")


def test_failed_list_refresh_fails_instead_of_skipping_packages(isolated_settings):
    # Without fresh lists, the new architecture's packages have no candidate
    # and would be skipped as if removed from the archive.
    aptget, _ = build(["wine32:i386"], return_codes = {" update": 1})
    assert not aptget.ensure_foreign_architectures()


###########################################################
# Uninstall and housekeeping
###########################################################

def test_uninstall_removes_every_package(isolated_settings):
    aptget, connection = build(["vim", "git"])
    assert aptget.uninstall()

    assert connection.ran("remove -y", "vim")
    assert connection.ran("remove -y", "git")


def test_uninstall_failure_stops(isolated_settings):
    aptget, connection = build(["vim", "git"], return_codes = {"remove -y vim": 1})
    assert not aptget.uninstall()

    assert not connection.ran("remove -y", "git")


def test_update_and_autoremove_report_exit_status(isolated_settings):
    aptget, _ = build(return_codes = {"autoremove": 1})
    assert aptget.update_package_lists()
    assert not aptget.auto_remove_packages()
