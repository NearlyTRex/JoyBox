# Imports
import os
import sys

# Local imports
import util
import packages
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
        self.env = self.config.get("env")
        self.winget_packages = packages.winget.get(self.env, [])
        self.winget_exe = self.config["Tools.WinGet"]["winget_exe"]
        self.winget_install_dir = os.path.expandvars(self.config["Tools.WinGet"]["winget_install_dir"])
        self.winget_tool = os.path.join(self.winget_install_dir, self.winget_exe)

    def IsInstalled(self):
        for pkg in self.winget_packages:
            if not self.IsPackageInstalled(pkg):
                return False
        return True

    def Install(self):
        util.LogInfo("Installing WinGet packages")
        for pkg in self.winget_packages:
            if not self.InstallPackage(pkg):
                util.LogError(f"Unable to install package {pkg}")
                return False
        return True

    def Uninstall(self):
        util.LogInfo("Uninstalling WinGet packages")
        for pkg in self.winget_packages:
            if not self.UninstallPackage(pkg):
                util.LogError(f"Unable to uninstall package {pkg}")
                return False
        return True

    def IsPackageInstalled(self, package):
        code = self.connection.RunReturncode([self.winget_tool, "list", "--name", package])
        return code == 0

    def InstallPackage(self, package):
        code = self.connection.RunReturncode([self.winget_tool, "install", "--accept-package-agreements", "--accept-source-agreements", "--id", package, "-e", "-h"])
        return code == 0

    def UninstallPackage(self, package):
        code = self.connection.RunReturncode([self.winget_tool, "uninstall", "--id", package, "-e", "-h"])
        return code == 0
