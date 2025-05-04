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
        self.flatpak_tool = os.path.join(self.flatpak_install_dir, self.flatpak_exe)

    def IsInstalled(self):
        for pkg in self.flatpak_packages:
            pkg_repo = pkg.get("repository")
            pkg_name = pkg.get("name")
            if not self.IsPackageInstalled(pkg_name):
                return False
        return True

    def Install(self):
        util.LogInfo("Installing Flatpak packages")
        for pkg in self.flatpak_packages:
            pkg_repo = pkg.get("repository")
            pkg_name = pkg.get("name")
            if not self.InstallPackage(pkg_repo, pkg_name):
                util.LogError(f"Unable to install package {pkg_name}")
                return False
        return True

    def Uninstall(self):
        util.LogInfo("Uninstalling Flatpak packages")
        for pkg in self.flatpak_packages:
            pkg_name = pkg.get("name")
            if not self.UninstallPackage(pkg_name):
                util.LogError(f"Unable to uninstall package {pkg_name}")
                return False
        return True

    def IsPackageInstalled(self, package):
        code = self.connection.RunReturncode(["flatpak", "info", package])
        return code == 0

    def UpdatePackages(self):
        code = self.connection.RunReturncode(["flatpak", "update", "-y"])
        return code == 0

    def InstallPackage(self, repository, package):
        code = self.connection.RunReturncode(["flatpak", "install", "-y", repository, package])
        return code == 0

    def UninstallPackage(self, package):
        code = self.connection.RunReturncode(["flatpak", "uninstall", "-y", package])
        return code == 0
