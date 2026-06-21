# Imports
import os
import sys

# Local imports
from joybox import platform_info
from joybox import settings

###########################################################
## AptGet
###########################################################

def get_aptget_tool():
    aptget_exe = settings.get_value("Tools.Apt", "apt_exe")
    aptget_install_dir = os.path.expandvars(settings.get_value("Tools.Apt", "apt_install_dir"))
    return os.path.join(aptget_install_dir, aptget_exe)

def get_aptget_install_tool():
    dpkg_exe = settings.get_value("Tools.Apt", "dpkg_exe")
    aptget_install_dir = os.path.expandvars(settings.get_value("Tools.Apt", "apt_install_dir"))
    return os.path.join(aptget_install_dir, dpkg_exe)

###########################################################
## WinGet
###########################################################

def get_winget_tool():
    winget_exe = settings.get_value("Tools.WinGet", "winget_exe")
    winget_install_dir = os.path.expandvars(settings.get_value("Tools.WinGet", "winget_install_dir"))
    return os.path.join(winget_install_dir, winget_exe)

###########################################################
## Flatpak
###########################################################

def get_flatpak_tool():
    flatpak_exe = settings.get_value("Tools.Flatpak", "flatpak_exe")
    flatpak_install_dir = os.path.expandvars(settings.get_value("Tools.Flatpak", "flatpak_install_dir"))
    return os.path.join(flatpak_install_dir, flatpak_exe)

###########################################################
## Python
###########################################################

def get_python_tool():
    python_exe = settings.get_value("Tools.Python", "python_exe")
    python_install_dir = os.path.expandvars(settings.get_value("Tools.Python", "python_install_dir"))
    return os.path.join(python_install_dir, python_exe)

def get_python_venv_dir():
    return os.path.expandvars(settings.get_value("Tools.Python", "python_venv_dir"))

def get_python_venv_python_tool():
    python_exe = settings.get_value("Tools.Python", "python_exe")
    if platform_info.is_windows_platform():
        return os.path.join(get_python_venv_dir(), "Scripts", python_exe)
    return os.path.join(get_python_venv_dir(), "bin", python_exe)

def get_python_venv_pip_tool():
    python_pip_exe = settings.get_value("Tools.Python", "python_pip_exe")
    if platform_info.is_windows_platform():
        return os.path.join(get_python_venv_dir(), "Scripts", python_pip_exe)
    return os.path.join(get_python_venv_dir(), "bin", python_pip_exe)

# Note: Curl, Tar, Git, and Gpg are resolved through the shared programs
# registry (programs.get_tool_program("Curl"/"Tar"/"Git"/"Gpg")), which reads
# the same Tools.* ini keys. They are intentionally not duplicated here.

###########################################################
## Docker
###########################################################

def get_docker_tool():
    docker_exe = settings.get_value("Tools.Docker", "docker_exe")
    docker_install_dir = os.path.expandvars(settings.get_value("Tools.Docker", "docker_install_dir"))
    return os.path.join(docker_install_dir, docker_exe)

def get_docker_compose_tool():
    docker_compose_exe = settings.get_value("Tools.Docker", "docker_compose_exe")
    docker_install_dir = os.path.expandvars(settings.get_value("Tools.Docker", "docker_install_dir"))
    return os.path.join(docker_install_dir, docker_compose_exe)

###########################################################
## System
###########################################################

def get_copy_tool():
    return settings.get_value("Tools.System", "cp")

def get_move_tool():
    return settings.get_value("Tools.System", "mv")

def get_remove_tool():
    return settings.get_value("Tools.System", "rm")

def get_link_tool():
    return settings.get_value("Tools.System", "ln")

def get_make_dir_tool():
    return settings.get_value("Tools.System", "mkdir")

def get_change_owner_tool():
    return settings.get_value("Tools.System", "chown")

def get_change_permission_tool():
    return settings.get_value("Tools.System", "chmod")
