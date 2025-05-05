# Imports
import os
import sys
import copy

# Local imports
import util
import connection

# Installer
class Installer:
    def __init__(
        self,
        config,
        connection,
        flags = util.RunFlags(),
        options = util.RunOptions()):
        self.config = config.Copy()
        self.connection = connection.Copy()
        self.flags = flags.Copy()
        self.options = options.Copy()

    def SetEnvironmentType(self, environment_type):
        self.config.SetValue("UserData.General", "environment_type", environment_type)

    def GetEnvironmentType(self):
        return self.config.GetValue("UserData.General", "environment_type")

    def IsInstalled(self):
        return False

    def Install(self):
        return False

    def Uninstall(self):
        return False

    ###########################
    ## AptGet
    ###########################

    def GetAptGetTool(self):
        aptget_exe = self.config.GetValue("Tools.Apt", "apt_exe")
        aptget_install_dir = os.path.expandvars(self.config.GetValue("Tools.Apt", "apt_install_dir"))
        return os.path.join(aptget_install_dir, aptget_exe)

    def GetAptGetInstallTool(self):
        dpkg_exe = self.config.GetValue("Tools.Apt", "dpkg_exe")
        aptget_install_dir = os.path.expandvars(self.config.GetValue("Tools.Apt", "apt_install_dir"))
        return os.path.join(aptget_install_dir, dpkg_exe)

    ###########################
    ## WinGet
    ###########################

    def GetWinGetTool(self):
        winget_exe = self.config.GetValue("Tools.WinGet", "winget_exe")
        winget_install_dir = os.path.expandvars(self.config.GetValue("Tools.WinGet", "winget_install_dir"))
        return os.path.join(winget_install_dir, winget_exe)

    ###########################
    ## Flatpak
    ###########################

    def GetFlatpakTool(self):
        flatpak_exe = self.config.GetValue("Tools.Flatpak", "flatpak_exe")
        flatpak_install_dir = os.path.expandvars(self.config.GetValue("Tools.Flatpak", "flatpak_install_dir"))
        return os.path.join(flatpak_install_dir, flatpak_exe)

    ###########################
    ## Python
    ###########################

    def GetPythonTool(self):
        python_exe = self.config.GetValue("Tools.Python", "python_exe")
        python_install_dir = os.path.expandvars(self.config.GetValue("Tools.Python", "python_install_dir"))
        return os.path.join(python_install_dir, python_exe)

    def GetPythonVenvDir(self):
        return os.path.expandvars(self.config.GetValue("Tools.Python", "python_venv_dir"))

    def GetPythonVenvPythonTool(self):
        python_exe = self.config.GetValue("Tools.Python", "python_exe")
        if util.IsWindowsPlatform():
            return os.path.join(self.GetPythonVenvDir(), "Scripts", python_exe)
        return os.path.join(self.GetPythonVenvDir(), "bin", python_exe)

    def GetPythonVenvPipTool(self):
        python_pip_exe = self.config.GetValue("Tools.Python", "python_pip_exe")
        if util.IsWindowsPlatform():
            return os.path.join(self.GetPythonVenvDir(), "Scripts", python_pip_exe)
        return os.path.join(self.GetPythonVenvDir(), "bin", python_pip_exe)

    ###########################
    ## Curl
    ###########################

    def GetCurlTool(self):
        curl_exe = self.config.GetValue("Tools.Curl", "curl_exe")
        curl_install_dir = os.path.expandvars(self.config.GetValue("Tools.Curl", "curl_install_dir"))
        return os.path.join(curl_install_dir, curl_exe)

    ###########################
    ## System
    ###########################

    def GetMoveTool(self):
        return self.config.GetValue("Tools.System", "mv")

    def GetRemoveTool(self):
        return self.config.GetValue("Tools.System", "rm")

    def GetLinkTool(self):
        return self.config.GetValue("Tools.System", "ln")

    def GetMakeDirTool(self):
        return self.config.GetValue("Tools.System", "mkdir")

    def GetSystemControlTool(self):
        return self.config.GetValue("Tools.System", "systemctl")
