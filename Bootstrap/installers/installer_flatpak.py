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

    def GetPackages(self):
        return packages.flatpak.get(self.get_environment_type(), [])

    def is_installed(self):
        for pkg in self.GetPackages():
            pkg_repo = pkg.get("repository")
            pkg_name = pkg.get("name")
            if not self.IsPackageInstalled(pkg_name):
                return False
        return True

    def install(self):
        util.log_info("Installing Flatpak packages")
        for pkg in self.GetPackages():
            pkg_repo = pkg.get("repository")
            pkg_name = pkg.get("name")
            if not self.InstallPackage(pkg_repo, pkg_name):
                util.log_error(f"Unable to install package {pkg_name}")
                return False
        return True

    def uninstall(self):
        util.log_info("Uninstalling Flatpak packages")
        for pkg in self.GetPackages():
            pkg_name = pkg.get("name")
            if not self.UninstallPackage(pkg_name):
                util.log_error(f"Unable to uninstall package {pkg_name}")
                return False
        return True

    def IsPackageInstalled(self, package):
        code = self.connection.run_blocking([self.flatpak_tool, "info", "--user", package])
        return code == 0

    def UpdatePackages(self):
        code = self.connection.run_blocking([self.flatpak_tool, "update", "--user", "-y"])
        return code == 0

    def InstallPackage(self, repository, package):
        code = self.connection.run_blocking([self.flatpak_tool, "install", "--user", "-y", repository, package])
        return code == 0

    def UninstallPackage(self, package):
        code = self.connection.run_blocking([self.flatpak_tool, "uninstall", "--user", "-y", package])
        return code == 0
