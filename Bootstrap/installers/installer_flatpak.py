# Imports
import os
import sys

# Local imports
import util
import packages
from . import installer

# Flatpak
class Flatpak(installer.Installer):
    def __init__(
        self,
        config,
        connection,
        flags = util.RunFlags(),
        options = util.RunOptions()):
        super().__init__(config, connection, flags, options)
        self.env = self.config.get("env")
        self.flatpak_packages = packages.flatpak.get(self.env, [])
        self.flatpak_exe = self.config["Tools.Flatpak"]["flatpak_exe"]
        self.flatpak_install_dir = os.path.expandvars(self.config["Tools.Flatpak"]["flatpak_install_dir"])
        self.flatpak_tool = os.path.join(flatpak_install_dir, flatpak_exe)

    def IsInstalled(self):
        for pkg in self.flatpak_packages:
            if not self.IsPackageInstalled(pkg):
                return False
        return True

    def Install(self):
        util.LogInfo("Installing Flatpak packages")
        for pkg in self.flatpak_packages:
            if not self.InstallPackage(pkg):
                util.LogError(f"Unable to install package {pkg}")
                return False
        return True

    def Uninstall(self):
        util.LogInfo("Uninstalling Flatpak packages")
        for pkg in self.flatpak_packages:
            if not self.UninstallPackage(pkg):
                util.LogError(f"Unable to uninstall package {pkg}")
                return False
        return True

    def IsPackageInstalled(self, package):
        code = self.connection.RunReturncode(["flatpak", "info", package])
        return code == 0

    def InstallPackage(self, package):
        code = self.connection.RunReturncode(["flatpak", "install", "-y", package])
        return code == 0

    def UninstallPackage(self, package):
        code = self.connection.RunReturncode(["flatpak", "uninstall", "-y", package])
        return code == 0
