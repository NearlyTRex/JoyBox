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
        self.env = self.config.get("env")
        self.aptget_packages = packages.aptget.get(self.env, [])
        self.aptget_exe = self.config["Tools.Apt"]["apt_exe"]
        self.dpkg_exe = self.config["Tools.Apt"]["dpkg_exe"]
        self.aptget_install_dir = os.path.expandvars(self.config["Tools.Apt"]["apt_install_dir"])
        self.aptget_tool = os.path.join(self.aptget_install_dir, self.aptget_exe)
        self.dpkg_tool = os.path.join(self.aptget_install_dir, self.dpkg_exe)

    def IsInstalled(self):
        for pkg in self.aptget_packages:
            if not self.IsPackageInstalled(pkg):
                return False
        return True

    def Install(self):
        util.LogInfo("Installing AptGet packages")
        for pkg in self.aptget_packages:
            if not self.InstallPackage(pkg):
                util.LogError(f"Unable to install package {pkg}")
                return False
        return True

    def Uninstall(self):
        util.LogInfo("Uninstalling AptGet packages")
        for pkg in self.aptget_packages:
            if not self.UninstallPackage(pkg):
                util.LogError(f"Unable to uninstall package {pkg}")
                return False
        return True

    def IsPackageInstalled(self, package):
        code = self.connection.RunReturncode([self.dpkg_tool, "-s", package])
        return code == 0

    def UpdatePackageLists(self):
        code = self.connection.RunReturncode(["sudo", self.aptget_tool, "update"])
        return code == 0

    def AutoRemovePackages(self):
        code = self.connection.RunReturncode(["sudo", self.aptget_tool, "autoremove"])
        return code == 0

    def InstallPackage(self, package):
        code = self.connection.RunReturncode(["sudo", self.aptget_tool, "install", "-y", package])
        return code == 0

    def UninstallPackage(self, package):
        code = self.connection.RunReturncode(["sudo", self.aptget_tool, "remove", "-y", package])
        return code == 0
