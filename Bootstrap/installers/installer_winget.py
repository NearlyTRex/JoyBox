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

    def GetPackages(self):
        return packages.winget.get(self.get_environment_type(), [])

    def is_installed(self):
        for pkg in self.GetPackages():
            if not self.IsPackageInstalled(pkg):
                return False
        return True

    def install(self):
        util.log_info("Installing WinGet packages")
        for pkg in self.GetPackages():
            if not self.InstallPackage(pkg):
                util.log_error(f"Unable to install package {pkg}")
                return False
        return True

    def uninstall(self):
        util.log_info("Uninstalling WinGet packages")
        for pkg in self.GetPackages():
            if not self.UninstallPackage(pkg):
                util.log_error(f"Unable to uninstall package {pkg}")
                return False
        return True

    def IsPackageInstalled(self, package):
        code = self.connection.run_blocking([self.winget_tool, "list", "--name", package])
        return code == 0

    def InstallPackage(self, package):
        code = self.connection.run_blocking([self.winget_tool, "install", "--accept-package-agreements", "--accept-source-agreements", "--id", package, "-e", "-h"])
        return code == 0

    def UninstallPackage(self, package):
        code = self.connection.run_blocking([self.winget_tool, "uninstall", "--id", package, "-e", "-h"])
        return code == 0
