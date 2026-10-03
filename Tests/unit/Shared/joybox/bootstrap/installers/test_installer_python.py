# Imports
import os

# Local imports
import joybox.bootstrap.installers as installers
import joybox.bootstrap.constants as constants
from joybox.bootstrap.installers import installer_python
from joybox import environment
from fakes import RecordingConnection


###########################################################
# joybox in the venv
#
# The commands and every import come from an editable install of this checkout,
# so installed means pip reports joybox as editable from exactly this checkout.
###########################################################

def repo_dir():
    return os.path.normpath(environment.get_repo_root(expand = True))


def build(pip_show = ""):
    connection = RecordingConnection(command_output = {"show joybox": pip_show})
    python = installers.Python(connection)
    python.get_packages = lambda: []
    return python, connection


def show_output(location):
    return "Name: joybox\nVersion: 0.1.0\nEditable project location: %s\n" % location


def test_install_installs_this_checkout_editable(isolated_settings):
    python, connection = build()
    connection.existing_paths.add(os.path.expandvars("$HOME/.venv"))
    python.install()

    assert any(
        command[1:] == ["install", "--editable", repo_dir() + "[dev,decompiler]"]
        for command in connection.commands)


def test_not_installed_is_not_installed(isolated_settings):
    python, _ = build()
    assert not python.is_installed()


def test_another_checkout_is_not_installed(isolated_settings):
    python, _ = build(show_output("/elsewhere/JoyBox"))
    assert not python.is_installed()


def test_this_checkout_is_installed(isolated_settings):
    python, _ = build(show_output(repo_dir()))
    assert python.is_installed()


def test_uninstall_removes_joybox(isolated_settings):
    python, connection = build()
    python.uninstall()

    assert any(command[1:] == ["uninstall", "-y", "joybox"] for command in connection.commands)


###########################################################
# Package descriptors
###########################################################

def test_string_package_descriptors():
    assert installer_python.get_python_package_id("rich") == "rich"
    assert installer_python.get_package_spec("rich") == ["rich"]
    assert installer_python.get_python_package_info("rich") == {
        "id": "rich", "name": "rich", "description": "", "category": ""}


def test_dict_package_descriptors():
    pkg = {"id": "rich", "name": "Rich", "description": "text", "category": "ui"}
    assert installer_python.get_python_package_id(pkg) == "rich"
    assert installer_python.get_python_package_info(pkg) == pkg
    assert installer_python.get_python_package_info({"id": "rich"})["name"] == "rich"
    assert installer_python.get_python_package_id({}) == ""


def test_spec_overrides_the_install_argument():
    assert installer_python.get_package_spec({"id": "rich"}) == ["rich"]
    assert installer_python.get_package_spec({"id": "rich", "spec": ""}) == ["rich"]
    assert installer_python.get_package_spec({"id": "x", "spec": "git+https://x.test/x"}) == ["git+https://x.test/x"]
    assert installer_python.get_package_spec({"id": "x", "spec": ["-e", 3]}) == ["-e", "3"]


###########################################################
# Packages
###########################################################

def with_packages(packages, **kwargs):
    connection = RecordingConnection(**kwargs)
    python = installers.Python(connection)
    python.get_packages = lambda: list(packages)
    return python, connection


def test_supported_environments(isolated_settings):
    python, _ = build()
    assert python.get_supported_environments() == [
        constants.EnvironmentType.LOCAL_UBUNTU, constants.EnvironmentType.LOCAL_WINDOWS]


def test_package_list_follows_environment_type(isolated_settings):
    assert isinstance(installers.Python(RecordingConnection()).get_packages(), list)


def test_installed_needs_every_package(isolated_settings):
    shown = {"show joybox": show_output(repo_dir())}
    python, _ = with_packages(["rich", {"id": "lxml"}], command_output = shown)
    assert python.is_installed()

    python, _ = with_packages(["rich", "lxml"], command_output = shown, return_codes = {"show lxml": 1})
    assert not python.is_installed()


def test_package_status_splits_installed_and_missing(isolated_settings):
    python, _ = with_packages(["rich", {"id": "lxml", "name": "LXML"}], return_codes = {"show lxml": 1})
    assert python.get_package_status() == {"installed": ["rich"], "missing": ["LXML"]}


def test_install_creates_missing_venv_then_installs_specs(isolated_settings):
    python, connection = with_packages(["rich", {"id": "x", "spec": ["git+https://x.test/x"]}])
    assert python.install()

    assert connection.ran("-m venv", os.path.expandvars("$HOME/.venv"))
    assert connection.ran("install --upgrade rich")
    assert connection.ran("install --upgrade git+https://x.test/x")


def test_install_uses_configured_venv_dir(isolated_settings):
    isolated_settings.set_value("Tools.Python", "python_venv_dir", "$HOME/custom-venv")
    python, connection = with_packages([])
    assert python.install()

    assert connection.ran("-m venv", os.path.expandvars("$HOME/custom-venv"))


def test_unset_venv_dir_defaults_to_home_venv(isolated_settings):
    isolated_settings.set_value("Tools.Python", "python_venv_dir", "")
    python, connection = with_packages([])
    assert python.install()

    assert connection.ran("-m venv", os.path.expandvars("$HOME/.venv"))


def test_venv_failure_fails_install(isolated_settings):
    python, connection = with_packages(["rich"], return_codes = {"-m venv": 1})
    assert not python.install()

    assert not connection.ran("--editable")


def test_joybox_failure_fails_install(isolated_settings):
    python, connection = with_packages(["rich"], return_codes = {"--editable": 1})
    connection.existing_paths.add(os.path.expandvars("$HOME/.venv"))
    assert not python.install()

    assert not connection.ran("--upgrade")


def test_package_failure_fails_install(isolated_settings):
    python, connection = with_packages([{"id": "rich", "name": "Rich"}, "lxml"], return_codes = {"--upgrade rich": 1})
    connection.existing_paths.add(os.path.expandvars("$HOME/.venv"))
    assert not python.install()

    assert not connection.ran("--upgrade lxml")


def test_install_package_accepts_a_plain_name(isolated_settings):
    python, connection = with_packages([])
    assert python.install_package("rich")
    assert connection.ran("install --upgrade rich")


def test_uninstall_removes_packages_before_joybox(isolated_settings):
    python, connection = with_packages(["rich"])
    assert python.uninstall()

    strings = connection.command_strings()
    assert [s for s in strings if "uninstall -y" in s][0].endswith("rich")


def test_uninstall_failure_stops(isolated_settings):
    python, connection = with_packages(["rich"], return_codes = {"uninstall -y rich": 1})
    assert not python.uninstall()

    assert not connection.ran("uninstall -y joybox")
