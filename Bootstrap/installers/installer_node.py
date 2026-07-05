# Imports
import os
import sys

# Local imports
import constants
import packages
from . import installer
from joybox import runoptions
from joybox import logger

# Extract package identifier from dict
def get_package_id(pkg):
    return pkg.get("id", pkg.get("name", ""))

# Get display info for a package
def get_package_info(pkg):
    pkg_id = get_package_id(pkg)
    return {
        "id": pkg_id,
        "name": pkg.get("name", pkg_id),
        "description": pkg.get("description", ""),
        "category": pkg.get("category", ""),
    }

# Node (global npm packages)
class Node(installer.Installer):
    def __init__(
        self,
        connection,
        flags = runoptions.RunFlags(),
        options = runoptions.RunOptions()):
        super().__init__(connection, flags, options)
        self.npm_tool = "npm"

    def get_supported_environments(self):
        return [
            constants.EnvironmentType.LOCAL_UBUNTU,
            constants.EnvironmentType.REMOTE_UBUNTU,
        ]

    def get_packages(self):
        return packages.node.get(self.get_environment_type(), [])

    def is_installed(self):
        for pkg in self.get_packages():
            if not self.is_package_installed(get_package_id(pkg)):
                return False
        return True

    def get_package_status(self):
        installed = []
        missing = []
        for pkg in self.get_packages():
            pkg_info = get_package_info(pkg)
            if self.is_package_installed(pkg_info["id"]):
                installed.append(pkg_info["name"])
            else:
                missing.append(pkg_info["name"])
        return {"installed": installed, "missing": missing}

    def install(self):
        logger.log_info("Installing npm global packages")
        for pkg in self.get_packages():
            pkg_info = get_package_info(pkg)
            if self.is_package_installed(pkg_info["id"]):
                continue
            logger.log_info(f"Installing {pkg_info['name']} via npm")
            if not self.install_package(pkg_info["id"]):
                logger.log_error(f"Unable to install package {pkg_info['name']}")
                return False
        return True

    def uninstall(self):
        logger.log_info("Uninstalling npm global packages")
        for pkg in self.get_packages():
            pkg_info = get_package_info(pkg)
            if not self.uninstall_package(pkg_info["id"]):
                logger.log_error(f"Unable to uninstall package {pkg_info['name']}")
                return False
        return True

    def is_package_installed(self, package):
        code = self.connection.run_blocking([self.npm_tool, "list", "-g", package])
        return code == 0

    def install_package(self, package):
        code = self.connection.run_blocking([self.npm_tool, "install", "-g", package], sudo=True)
        return code == 0

    def uninstall_package(self, package):
        code = self.connection.run_blocking([self.npm_tool, "uninstall", "-g", package], sudo=True)
        return code == 0
