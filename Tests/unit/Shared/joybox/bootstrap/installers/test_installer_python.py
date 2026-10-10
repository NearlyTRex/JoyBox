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


def build(pip_show = "", installed_requirements = ""):
    connection = RecordingConnection(command_output = {
        "show joybox": pip_show,
        "importlib.metadata": installed_requirements})
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


REQUIREMENTS_IN = """# What joybox uses
libWiiPy
python-dateutil
pyuac; sys_platform == 'win32'
"""

PYPROJECT = """[project.optional-dependencies]
decompiler = ["pyghidra"]
dev = ["coverage", "pytest"]
other = ["unrelated"]
"""


def build_in_checkout(tmp_path, monkeypatch, installed_requirements):
    (tmp_path / "requirements.in").write_text(REQUIREMENTS_IN)
    (tmp_path / "pyproject.toml").write_text(PYPROJECT)
    monkeypatch.setattr(installers.Python, "get_repo_dir", lambda self: str(tmp_path))
    return build(show_output(str(tmp_path)), installed_requirements = "\n".join(installed_requirements))


def test_declared_requirements_include_the_venv_extras(isolated_settings, tmp_path, monkeypatch):
    python, _ = build_in_checkout(tmp_path, monkeypatch, [])
    assert python.get_declared_requirement_names() == {
        "libwiipy", "python-dateutil", "pyuac", "pyghidra", "coverage", "pytest"}


def test_current_metadata_is_installed(isolated_settings, tmp_path, monkeypatch):
    python, _ = build_in_checkout(tmp_path, monkeypatch, [
        "libWiiPy", "python-dateutil", 'pyuac; sys_platform == "win32"',
        'pyghidra; extra == "decompiler"', 'coverage; extra == "dev"', 'pytest; extra == "dev"'])
    assert python.is_installed()


def test_metadata_missing_a_new_requirement_is_not_installed(isolated_settings, tmp_path, monkeypatch):
    python, _ = build_in_checkout(tmp_path, monkeypatch, [
        "python-dateutil", "pyuac", "pyghidra", "coverage", "pytest"])
    assert not python.is_installed()


def test_metadata_with_a_dropped_requirement_is_not_installed(isolated_settings, tmp_path, monkeypatch):
    python, _ = build_in_checkout(tmp_path, monkeypatch, [
        "libWiiPy", "python-dateutil", "pyuac", "pyghidra", "coverage", "pytest", "retired"])
    assert not python.is_installed()


def test_requirement_names_ignore_versions_markers_and_comments():
    assert installer_python.get_requirement_names([
        "# comment",
        "",
        "Python_Dateutil>=2.8 ; python_version >= '3'",
        "foo[bar]==1.0  # trailing",
        "baz @ https://example.com/baz.whl",
    ]) == {"python-dateutil", "foo", "baz"}


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


###########################################################
# Isolated packages
#
# A tool that pins its dependencies exactly gets a venv of its own, so it
# cannot move the shared venv's packages, and its commands are linked onto the
# PATH.
###########################################################

AIDER = {"id": "aider-chat", "name": "Aider", "isolated": True, "commands": ["aider"]}


def tools_dir():
    return os.path.expandvars("$HOME/.local/share/joybox/pytools")


def aider_bin():
    return os.path.join(tools_dir(), "aider-chat", "bin")


def test_only_marked_packages_are_isolated():
    assert installer_python.is_isolated_package(AIDER) is True
    assert installer_python.is_isolated_package({"id": "rich"}) is False
    assert installer_python.is_isolated_package("rich") is False
    assert installer_python.get_package_commands(AIDER) == ["aider"]
    assert installer_python.get_package_commands("rich") == []


def test_an_isolated_package_gets_its_own_venv(isolated_settings):
    python, connection = with_packages([AIDER])
    connection.existing_paths.add(os.path.expandvars("$HOME/.venv"))

    assert python.install()

    assert connection.ran("-m venv", os.path.join(tools_dir(), "aider-chat"))
    assert connection.ran(os.path.join(aider_bin(), "pip3"), "install --upgrade aider-chat")
    assert not connection.ran(os.path.expandvars("$HOME/.venv/bin/pip3"), "aider-chat")


def test_an_existing_isolated_venv_is_reused(isolated_settings):
    python, connection = with_packages([AIDER])
    connection.existing_paths.update([os.path.expandvars("$HOME/.venv"), os.path.join(tools_dir(), "aider-chat")])

    assert python.install()

    assert not connection.ran("-m venv", "aider-chat")


def test_an_isolated_package_commands_are_linked_onto_the_path(isolated_settings):
    python, connection = with_packages([AIDER])
    connection.existing_paths.add(os.path.expandvars("$HOME/.venv"))

    assert python.install()

    links = [call[1] for call in connection.called("link_file_or_directory")]
    assert links == [(os.path.join(aider_bin(), "aider"),
        os.path.join(os.path.expanduser("~"), ".local", "bin", "aider"))]


def test_the_tools_dir_follows_the_setting(isolated_settings, tmp_path):
    isolated_settings.set_value("Tools.Python", "python_tools_dir", str(tmp_path / "tools"))
    python, connection = with_packages([AIDER])
    connection.existing_paths.add(os.path.expandvars("$HOME/.venv"))

    assert python.install()

    assert connection.ran("-m venv", str(tmp_path / "tools" / "aider-chat"))


def test_a_failed_isolated_venv_fails_the_install(isolated_settings):
    python, connection = with_packages([AIDER], return_codes = {"aider-chat": 1})
    connection.existing_paths.add(os.path.expandvars("$HOME/.venv"))

    assert not python.install()
    assert connection.called("link_file_or_directory") == []


def test_a_failed_isolated_install_links_nothing(isolated_settings):
    python, connection = with_packages([AIDER], return_codes = {"install --upgrade aider-chat": 1})
    connection.existing_paths.add(os.path.expandvars("$HOME/.venv"))

    assert not python.install()
    assert connection.called("link_file_or_directory") == []


def test_a_failed_link_fails_the_install(isolated_settings, monkeypatch):
    python, connection = with_packages([AIDER])
    connection.existing_paths.add(os.path.expandvars("$HOME/.venv"))
    monkeypatch.setattr(connection, "link_file_or_directory", lambda src, dest, sudo = False: False)

    assert not python.install()


def test_on_windows_the_isolated_scripts_go_on_the_path(isolated_settings, monkeypatch):
    python, connection = with_packages([AIDER])
    monkeypatch.setattr(installer_python.platform_info, "is_windows_platform", lambda: True)
    connection.existing_paths.add(os.path.expandvars("$HOME/.venv"))
    added = []
    monkeypatch.setattr(connection, "add_to_path", lambda src: added.append(src) or True)

    assert python.install_isolated_package(AIDER)

    assert added == [os.path.join(tools_dir(), "aider-chat", "Scripts")]
    assert connection.called("link_file_or_directory") == []


def test_an_isolated_package_is_checked_in_its_own_venv(isolated_settings):
    shown = {"show joybox": show_output(repo_dir())}
    python, connection = with_packages([AIDER], command_output = shown)

    assert python.is_installed()
    assert connection.ran(os.path.join(aider_bin(), "pip3"), "show aider-chat")

    python, _ = with_packages([AIDER], command_output = shown, return_codes = {"show aider-chat": 1})
    assert not python.is_installed()
    assert python.get_package_status() == {"installed": [], "missing": ["Aider"]}


def test_uninstall_removes_the_links_and_the_venv(isolated_settings):
    link = os.path.join(os.path.expanduser("~"), ".local", "bin", "aider")
    venv = os.path.join(tools_dir(), "aider-chat")
    python, connection = with_packages([AIDER], existing_paths = [link, venv])

    assert python.uninstall()

    assert connection.removed_paths == [link, venv]
    assert not connection.ran("uninstall -y aider-chat")


def test_uninstalling_an_absent_isolated_package_succeeds(isolated_settings):
    python, connection = with_packages([AIDER])

    assert python.uninstall_isolated_package(AIDER)
    assert connection.removed_paths == []


def test_an_empty_tools_dir_setting_falls_back_to_the_default(isolated_settings):
    isolated_settings.set_value("Tools.Python", "python_tools_dir", "")
    python, _ = with_packages([AIDER])

    assert python.get_tools_dir() == tools_dir()


def test_on_windows_uninstall_has_no_links_to_remove(isolated_settings, monkeypatch):
    venv = os.path.join(tools_dir(), "aider-chat")
    python, connection = with_packages([AIDER], existing_paths = [venv])
    monkeypatch.setattr(installer_python.platform_info, "is_windows_platform", lambda: True)

    assert python.uninstall_isolated_package(AIDER)
    assert connection.removed_paths == [venv]
