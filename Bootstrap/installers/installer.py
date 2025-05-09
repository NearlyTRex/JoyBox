# Imports
import os
import sys
import copy

# Local imports
import util
import tools
import connection

# Installer
class Installer:
    def __init__(
        self,
        config,
        connection,
        flags = util.RunFlags(),
        options = util.RunOptions()):

        # Copy inputs
        self.config = config.Copy()
        self.connection = connection.Copy()
        self.flags = flags.Copy()
        self.options = options.Copy()

        # Setup tools
        if util.IsWindowsPlatform():
            self.winget_tool = tools.GetWinGetTool(self.config)
        else:
            self.aptget_tool = tools.GetAptGetTool(self.config)
            self.aptgetinstall_tool = tools.GetAptGetInstallTool(self.config)
            self.flatpak_tool = tools.GetFlatpakTool(self.config)
        self.python_tool = tools.GetPythonTool(self.config)
        self.python_venv_pip_tool = tools.GetPythonVenvPipTool(self.config)
        self.gpg_tool = tools.GetGpgTool(self.config)
        self.docker_tool = tools.GetDockerTool(self.config)
        self.docker_compose_tool = tools.GetDockerComposeTool(self.config)
        self.nginx_manager_tool = "/usr/local/bin/manager_nginx.sh"
        self.cert_manager_tool = "/usr/local/bin/manager_certbot.sh"
        self.azuracast_manager_tool = "/usr/local/bin/manager_azuracast.sh"

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
