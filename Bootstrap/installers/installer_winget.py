# Imports
import os
import sys

# Local imports
import util
import constants
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

    def get_supported_environments(self):
        return [
            constants.EnvironmentType.LOCAL_WINDOWS,
        ]

    def get_packages(self):
        return packages.winget.get(self.get_environment_type(), [])

    def is_installed(self):
        for pkg in self.get_packages():
            if not self.is_package_installed(pkg):
                return False
        return True

    def get_package_status(self):
        installed = []
        missing = []
        for pkg in self.get_packages():
            if self.is_package_installed(pkg):
                installed.append(pkg)
            else:
                missing.append(pkg)
        return {"installed": installed, "missing": missing}

    def install(self):
        util.log_info("Installing WinGet packages")
        for pkg in self.get_packages():
            if not self.install_package(pkg):
                util.log_error(f"Unable to install package {pkg}")
                return False
        return True

    def uninstall(self):
        util.log_info("Uninstalling WinGet packages")
        for pkg in self.get_packages():
            if not self.uninstall_package(pkg):
                util.log_error(f"Unable to uninstall package {pkg}")
                return False
        return True

    def is_package_installed(self, package):
        code = self.connection.run_blocking([self.winget_tool, "list", "--name", package])
        return code == 0

    def install_package(self, package):
        code = self.connection.run_blocking([self.winget_tool, "install", "--accept-package-agreements", "--accept-source-agreements", "--id", package, "-e", "-h"])
        return code == 0

    def uninstall_package(self, package):
        code = self.connection.run_blocking([self.winget_tool, "uninstall", "--id", package, "-e", "-h"])
        return code == 0
