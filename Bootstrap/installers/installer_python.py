# Imports
import os
import sys

# Local imports
import util
import packages
from . import installer

# Python
class Python(installer.Installer):
    def __init__(
        self,
        config,
        connection,
        flags = util.RunFlags(),
        options = util.RunOptions()):
        super().__init__(config, connection, flags, options)

    def GetPackages(self):
        return packages.python.get(self.get_environment_type(), [])

    def is_installed(self):
        for pkg in self.GetPackages():
            if not self.IsPackageInstalled(pkg):
                return False
        return True

    def install(self):
        util.log_info("Installing Python packages")
        for pkg in self.GetPackages():
            if not self.InstallPackage(pkg):
                util.log_error(f"Unable to install package {pkg}")
                return False
        return True

    def uninstall(self):
        util.log_info("Uninstalling Python packages")
        for pkg in self.GetPackages():
            if not self.UninstallPackage(pkg):
                util.log_error(f"Unable to uninstall package {pkg}")
                return False
        return True

    def CreateVirtualEnvironment(self, venv_dir):
        code = self.connection.run_blocking([self.python_tool, "-m", "venv", venv_dir])
        return code == 0

    def IsPackageInstalled(self, package):
        code = self.connection.run_blocking([self.python_venv_pip_tool, "show", package])
        return code == 0

    def InstallPackage(self, package):
        code = self.connection.run_blocking([self.python_venv_pip_tool, "install", "--upgrade", package])
        return code == 0

    def UninstallPackage(self, package):
        code = self.connection.run_blocking([self.python_venv_pip_tool, "uninstall", "-y", package])
        return code == 0
