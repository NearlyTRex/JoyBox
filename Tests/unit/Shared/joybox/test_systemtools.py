# Imports
import os

# Third-party imports
import pytest

# Local imports
from joybox import systemtools


###########################################################
# System tool paths
#
# Every tool path is composed from a configured install directory and
# executable name, so an unexpanded variable or a dropped directory sends a
# command at the wrong binary.
###########################################################

# The package-manager tools are platform-scoped: winget exists only on Windows
# and apt only elsewhere, and their settings sections are gated to match.
from joybox import platform_info

if platform_info.is_windows_platform():
    PACKAGE_ACCESSORS = ["get_winget_tool"]
else:
    PACKAGE_ACCESSORS = ["get_aptget_tool", "get_aptget_install_tool", "get_flatpak_tool"]

TOOL_ACCESSORS = PACKAGE_ACCESSORS + [
    "get_python_tool", "get_docker_tool", "get_docker_compose_tool",
]

COREUTIL_ACCESSORS = [
    "get_copy_tool", "get_move_tool", "get_remove_tool", "get_link_tool",
    "get_make_dir_tool", "get_change_owner_tool", "get_change_permission_tool",
]


@pytest.mark.parametrize("accessor", TOOL_ACCESSORS + COREUTIL_ACCESSORS)
def test_every_tool_resolves_to_a_path(isolated_settings, accessor):
    resolved = getattr(systemtools, accessor)()

    assert isinstance(resolved, str)
    assert resolved


@pytest.mark.parametrize("accessor", TOOL_ACCESSORS)
def test_no_tool_path_leaves_a_variable_unexpanded(isolated_settings, accessor):
    # An unexpanded %VAR% or $VAR becomes a literal directory name.
    resolved = getattr(systemtools, accessor)()

    assert "%" not in resolved
    assert "$" not in resolved


@pytest.mark.parametrize("accessor", TOOL_ACCESSORS)
def test_a_tool_path_ends_with_its_executable(isolated_settings, accessor):
    resolved = getattr(systemtools, accessor)()

    assert os.path.basename(resolved)


@pytest.mark.skipif(platform_info.is_windows_platform(), reason = "apt is not a Windows tool")
def test_a_configured_install_directory_is_used(isolated_settings):
    isolated_settings.set_value("Tools.Apt", "apt_install_dir", "/custom/bin")
    isolated_settings.set_value("Tools.Apt", "apt_exe", "apt-get")

    assert systemtools.get_aptget_tool() == os.path.join("/custom", "bin", "apt-get")


@pytest.mark.skipif(platform_info.is_windows_platform(), reason = "apt is not a Windows tool")
def test_an_environment_variable_in_the_directory_expands(isolated_settings, monkeypatch):
    monkeypatch.setenv("JOYBOX_TOOL_ROOT", "/expanded")
    isolated_settings.set_value("Tools.Apt", "apt_install_dir", "$JOYBOX_TOOL_ROOT/bin")
    isolated_settings.set_value("Tools.Apt", "apt_exe", "apt-get")

    assert systemtools.get_aptget_tool().startswith("/expanded")


@pytest.mark.skipif(platform_info.is_windows_platform(), reason = "apt is not a Windows tool")
def test_apt_and_dpkg_share_the_install_directory(isolated_settings):
    isolated_settings.set_value("Tools.Apt", "apt_install_dir", "/custom/bin")

    assert os.path.dirname(systemtools.get_aptget_tool()) == \
        os.path.dirname(systemtools.get_aptget_install_tool())


@pytest.mark.skipif(platform_info.is_windows_platform(), reason = "apt is not a Windows tool")
def test_apt_and_dpkg_are_different_binaries(isolated_settings):
    assert systemtools.get_aptget_tool() != systemtools.get_aptget_install_tool()


###########################################################
# Python virtual environment
###########################################################

def test_the_venv_directory_expands(isolated_settings, monkeypatch):
    monkeypatch.setenv("JOYBOX_VENV", "/expanded/venv")
    isolated_settings.set_value("Tools.Python", "python_venv_dir", "$JOYBOX_VENV")

    assert systemtools.get_python_venv_dir() == "/expanded/venv"


def test_the_venv_python_sits_inside_the_venv(isolated_settings):
    isolated_settings.set_value("Tools.Python", "python_venv_dir", "/venv")

    assert systemtools.get_python_venv_python_tool().startswith("/venv")


def test_the_venv_pip_sits_inside_the_venv(isolated_settings):
    isolated_settings.set_value("Tools.Python", "python_venv_dir", "/venv")

    assert systemtools.get_python_venv_pip_tool().startswith("/venv")


def test_the_venv_binaries_share_a_directory(isolated_settings):
    isolated_settings.set_value("Tools.Python", "python_venv_dir", "/venv")

    assert os.path.dirname(systemtools.get_python_venv_python_tool()) == \
        os.path.dirname(systemtools.get_python_venv_pip_tool())


def test_the_venv_layout_follows_the_platform(isolated_settings):
    # Windows puts binaries in Scripts/, unix in bin/.
    isolated_settings.set_value("Tools.Python", "python_venv_dir", "/venv")
    expected = "Scripts" if platform_info.is_windows_platform() else "bin"

    assert expected in systemtools.get_python_venv_python_tool()


def test_the_venv_python_differs_from_the_system_python(isolated_settings):
    isolated_settings.set_value("Tools.Python", "python_install_dir", "/usr/bin")
    isolated_settings.set_value("Tools.Python", "python_venv_dir", "/venv")

    assert systemtools.get_python_tool() != systemtools.get_python_venv_python_tool()


###########################################################
# Coreutils
###########################################################

def test_the_coreutils_are_distinct(isolated_settings):
    resolved = {getattr(systemtools, accessor)() for accessor in COREUTIL_ACCESSORS}

    assert len(resolved) == len(COREUTIL_ACCESSORS)
