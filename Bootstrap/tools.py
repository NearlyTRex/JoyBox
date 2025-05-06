# Imports
import os
import sys

###########################################################
## AptGet
###########################################################

def GetAptGetTool(config):
    aptget_exe = config.GetValue("Tools.Apt", "apt_exe")
    aptget_install_dir = os.path.expandvars(config.GetValue("Tools.Apt", "apt_install_dir"))
    return os.path.join(aptget_install_dir, aptget_exe)

def GetAptGetInstallTool(config):
    dpkg_exe = config.GetValue("Tools.Apt", "dpkg_exe")
    aptget_install_dir = os.path.expandvars(config.GetValue("Tools.Apt", "apt_install_dir"))
    return os.path.join(aptget_install_dir, dpkg_exe)

###########################################################
## WinGet
###########################################################

def GetWinGetTool(config):
    winget_exe = config.GetValue("Tools.WinGet", "winget_exe")
    winget_install_dir = os.path.expandvars(config.GetValue("Tools.WinGet", "winget_install_dir"))
    return os.path.join(winget_install_dir, winget_exe)

###########################################################
## Flatpak
###########################################################

def GetFlatpakTool(config):
    flatpak_exe = config.GetValue("Tools.Flatpak", "flatpak_exe")
    flatpak_install_dir = os.path.expandvars(config.GetValue("Tools.Flatpak", "flatpak_install_dir"))
    return os.path.join(flatpak_install_dir, flatpak_exe)

###########################################################
## Python
###########################################################

def GetPythonTool(config):
    python_exe = config.GetValue("Tools.Python", "python_exe")
    python_install_dir = os.path.expandvars(config.GetValue("Tools.Python", "python_install_dir"))
    return os.path.join(python_install_dir, python_exe)

def GetPythonVenvDir(config):
    return os.path.expandvars(config.GetValue("Tools.Python", "python_venv_dir"))

def GetPythonVenvPythonTool(config):
    python_exe = config.GetValue("Tools.Python", "python_exe")
    if util.IsWindowsPlatform():
        return os.path.join(config.GetPythonVenvDir(), "Scripts", python_exe)
    return os.path.join(config.GetPythonVenvDir(), "bin", python_exe)

def GetPythonVenvPipTool(config):
    python_pip_exe = config.GetValue("Tools.Python", "python_pip_exe")
    if util.IsWindowsPlatform():
        return os.path.join(config.GetPythonVenvDir(), "Scripts", python_pip_exe)
    return os.path.join(config.GetPythonVenvDir(), "bin", python_pip_exe)

###########################################################
## Curl
###########################################################

def GetCurlTool(config):
    curl_exe = config.GetValue("Tools.Curl", "curl_exe")
    curl_install_dir = os.path.expandvars(config.GetValue("Tools.Curl", "curl_install_dir"))
    return os.path.join(curl_install_dir, curl_exe)

###########################################################
## Tar
###########################################################

def GetTarTool(config):
    tar_exe = config.GetValue("Tools.Tar", "tar_exe")
    tar_install_dir = os.path.expandvars(config.GetValue("Tools.Tar", "tar_install_dir"))
    return os.path.join(tar_install_dir, tar_exe)

###########################################################
## Git
###########################################################

def GetGitTool(config):
    git_exe = config.GetValue("Tools.Git", "git_exe")
    git_install_dir = os.path.expandvars(config.GetValue("Tools.Git", "git_install_dir"))
    return os.path.join(git_install_dir, git_exe)

###########################################################
## Gpg
###########################################################

def GetGpgTool(config):
    gpg_exe = config.GetValue("Tools.Gpg", "gpg_exe")
    gpg_install_dir = os.path.expandvars(config.GetValue("Tools.Gpg", "gpg_install_dir"))
    return os.path.join(gpg_install_dir, gpg_exe)

###########################################################
## Docker
###########################################################

def GetDockerTool(config):
    docker_exe = config.GetValue("Tools.Docker", "docker_exe")
    docker_install_dir = os.path.expandvars(config.GetValue("Tools.Docker", "docker_install_dir"))
    return os.path.join(docker_install_dir, docker_exe)

def GetDockerComposeTool(config):
    docker_compose_exe = config.GetValue("Tools.Docker", "docker_compose_exe")
    docker_install_dir = os.path.expandvars(config.GetValue("Tools.Docker", "docker_install_dir"))
    return os.path.join(docker_install_dir, docker_compose_exe)

###########################################################
## System
###########################################################

def GetCopyTool(config):
    return config.GetValue("Tools.System", "cp")

def GetMoveTool(config):
    return config.GetValue("Tools.System", "mv")

def GetRemoveTool(config):
    return config.GetValue("Tools.System", "rm")

def GetLinkTool(config):
    return config.GetValue("Tools.System", "ln")

def GetMakeDirTool(config):
    return config.GetValue("Tools.System", "mkdir")

def GetChangeOwnerTool(config):
    return config.GetValue("Tools.System", "chown")

def GetChangePermissionTool(config):
    return config.GetValue("Tools.System", "chmod")
