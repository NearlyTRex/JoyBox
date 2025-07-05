# Imports
import os
import sys

# Local imports
import util

###########################################################
## AptGet
###########################################################

def get_aptget_tool(config):
    aptget_exe = config.get_value("Tools.Apt", "apt_exe")
    aptget_install_dir = os.path.expandvars(config.get_value("Tools.Apt", "apt_install_dir"))
    return os.path.join(aptget_install_dir, aptget_exe)

def get_aptget_install_tool(config):
    dpkg_exe = config.get_value("Tools.Apt", "dpkg_exe")
    aptget_install_dir = os.path.expandvars(config.get_value("Tools.Apt", "apt_install_dir"))
    return os.path.join(aptget_install_dir, dpkg_exe)

###########################################################
## WinGet
###########################################################

def get_winget_tool(config):
    winget_exe = config.get_value("Tools.WinGet", "winget_exe")
    winget_install_dir = os.path.expandvars(config.get_value("Tools.WinGet", "winget_install_dir"))
    return os.path.join(winget_install_dir, winget_exe)

###########################################################
## Flatpak
###########################################################

def get_flatpak_tool(config):
    flatpak_exe = config.get_value("Tools.Flatpak", "flatpak_exe")
    flatpak_install_dir = os.path.expandvars(config.get_value("Tools.Flatpak", "flatpak_install_dir"))
    return os.path.join(flatpak_install_dir, flatpak_exe)

###########################################################
## Python
###########################################################

def get_python_tool(config):
    python_exe = config.get_value("Tools.Python", "python_exe")
    python_install_dir = os.path.expandvars(config.get_value("Tools.Python", "python_install_dir"))
    return os.path.join(python_install_dir, python_exe)

def get_python_venv_dir(config):
    return os.path.expandvars(config.get_value("Tools.Python", "python_venv_dir"))

def get_python_venv_python_tool(config):
    python_exe = config.get_value("Tools.Python", "python_exe")
    if util.is_windows_platform():
        return os.path.join(get_python_venv_dir(config), "Scripts", python_exe)
    return os.path.join(get_python_venv_dir(config), "bin", python_exe)

def get_python_venv_pip_tool(config):
    python_pip_exe = config.get_value("Tools.Python", "python_pip_exe")
    if util.is_windows_platform():
        return os.path.join(get_python_venv_dir(config), "Scripts", python_pip_exe)
    return os.path.join(get_python_venv_dir(config), "bin", python_pip_exe)

###########################################################
## Curl
###########################################################

def get_curl_tool(config):
    curl_exe = config.get_value("Tools.Curl", "curl_exe")
    curl_install_dir = os.path.expandvars(config.get_value("Tools.Curl", "curl_install_dir"))
    return os.path.join(curl_install_dir, curl_exe)

###########################################################
## Tar
###########################################################

def get_tar_tool(config):
    tar_exe = config.get_value("Tools.Tar", "tar_exe")
    tar_install_dir = os.path.expandvars(config.get_value("Tools.Tar", "tar_install_dir"))
    return os.path.join(tar_install_dir, tar_exe)

###########################################################
## Git
###########################################################

def get_git_tool(config):
    git_exe = config.get_value("Tools.Git", "git_exe")
    git_install_dir = os.path.expandvars(config.get_value("Tools.Git", "git_install_dir"))
    return os.path.join(git_install_dir, git_exe)

###########################################################
## Gpg
###########################################################

def get_gpg_tool(config):
    gpg_exe = config.get_value("Tools.Gpg", "gpg_exe")
    gpg_install_dir = os.path.expandvars(config.get_value("Tools.Gpg", "gpg_install_dir"))
    return os.path.join(gpg_install_dir, gpg_exe)

###########################################################
## Docker
###########################################################

def get_docker_tool(config):
    docker_exe = config.get_value("Tools.Docker", "docker_exe")
    docker_install_dir = os.path.expandvars(config.get_value("Tools.Docker", "docker_install_dir"))
    return os.path.join(docker_install_dir, docker_exe)

def get_docker_compose_tool(config):
    docker_compose_exe = config.get_value("Tools.Docker", "docker_compose_exe")
    docker_install_dir = os.path.expandvars(config.get_value("Tools.Docker", "docker_install_dir"))
    return os.path.join(docker_install_dir, docker_compose_exe)

###########################################################
## System
###########################################################

def get_copy_tool(config):
    return config.get_value("Tools.System", "cp")

def get_move_tool(config):
    return config.get_value("Tools.System", "mv")

def get_remove_tool(config):
    return config.get_value("Tools.System", "rm")

def get_link_tool(config):
    return config.get_value("Tools.System", "ln")

def get_make_dir_tool(config):
    return config.get_value("Tools.System", "mkdir")

def get_change_owner_tool(config):
    return config.get_value("Tools.System", "chown")

def get_change_permission_tool(config):
    return config.get_value("Tools.System", "chmod")
