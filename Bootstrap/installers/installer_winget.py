# Imports
import os
import sys

# Local imports
import util
import packages
import tools
from . import installer

# WinGet
class WinGet(installer.Installer):
    def __init__(
        self,
        config,
        connection,
        flags = util.RunFlags(),
        options = util.RunOptions()):
        super().__init__(config, connection, flags, options)
        self.winget_tool = tools.GetWinGetTool(self.config)

    def GetPackages(self):
        return packages.winget.get(self.GetEnvironmentType(), [])

    def IsInstalled(self):
        for pkg in self.GetPackages():
            if not self.IsPackageInstalled(pkg):
                return False
        return True

    def Install(self):
        util.LogInfo("Installing WinGet packages")
        for pkg in self.GetPackages():
            if not self.InstallPackage(pkg):
                util.LogError(f"Unable to install package {pkg}")
                return False
        return True

    def Uninstall(self):
        util.LogInfo("Uninstalling WinGet packages")
        for pkg in self.GetPackages():
            if not self.UninstallPackage(pkg):
                util.LogError(f"Unable to uninstall package {pkg}")
                return False
        return True

    def IsPackageInstalled(self, package):
        code = self.connection.RunBlocking([self.winget_tool, "list", "--name", package])
        return code == 0

    def InstallPackage(self, package):
        code = self.connection.RunBlocking([self.winget_tool, "install", "--accept-package-agreements", "--accept-source-agreements", "--id", package, "-e", "-h"])
        return code == 0

    def UninstallPackage(self, package):
        code = self.connection.RunBlocking([self.winget_tool, "uninstall", "--id", package, "-e", "-h"])
        return code == 0
