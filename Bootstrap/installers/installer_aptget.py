# Imports
import os
import sys

# Local imports
import util
import packages
from . import installer

# AptGet
class AptGet(installer.Installer):
    def __init__(
        self,
        config,
        connection,
        flags = util.RunFlags(),
        options = util.RunOptions()):
        super().__init__(config, connection, flags, options)

    def GetPackages(self):
        return packages.aptget.get(self.get_environment_type(), [])

    def is_installed(self):
        for pkg in self.GetPackages():
            if not self.IsPackageInstalled(pkg):
                return False
        return True

    def install(self):
        util.log_info("Installing AptGet packages")
        for pkg in self.GetPackages():
            if not self.InstallPackage(pkg):
                util.log_error(f"Unable to install package {pkg}")
                return False
        return True

    def uninstall(self):
        util.log_info("Uninstalling AptGet packages")
        for pkg in self.GetPackages():
            if not self.UninstallPackage(pkg):
                util.log_error(f"Unable to uninstall package {pkg}")
                return False
        return True

    def IsPackageInstalled(self, package):
        output = self.connection.run_output([self.aptgetinstall_tool, "-s", package])
        return "Status: install ok installed" in output

    def UpdatePackageLists(self):
        code = self.connection.run_blocking([self.aptget_tool, "update"], sudo = True)
        return code == 0

    def AutoRemovePackages(self):
        code = self.connection.run_blocking([self.aptget_tool, "autoremove", "-y"], sudo = True)
        return code == 0

    def InstallPackage(self, package):
        code = self.connection.run_blocking([self.aptget_tool, "install", "-y", package], sudo = True)
        return code == 0

    def UninstallPackage(self, package):
        code = self.connection.run_blocking([self.aptget_tool, "remove", "-y", package], sudo = True)
        return code == 0
