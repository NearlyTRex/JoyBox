# Imports
import os
import sys

# Local imports
import util
import constants
import packages
from . import installer

# Extract package identifier from string or dict
def get_package_id(pkg):
    if isinstance(pkg, str):
        return pkg
    return pkg.get("id", "")

# Get display info for a package
def get_package_info(pkg):
    if isinstance(pkg, str):
        return {"id": pkg, "name": pkg, "description": "", "category": ""}
    return {
        "id": pkg.get("id", ""),
        "name": pkg.get("name", pkg.get("id", "")),
        "description": pkg.get("description", ""),
        "category": pkg.get("category", "")
    }

# AptGet
class AptGet(installer.Installer):
    def __init__(
        self,
        config,
        connection,
        flags = util.RunFlags(),
        options = util.RunOptions()):
        super().__init__(config, connection, flags, options)

    def get_supported_environments(self):
        return [
            constants.EnvironmentType.LOCAL_UBUNTU,
            constants.EnvironmentType.REMOTE_UBUNTU,
        ]

    def get_packages(self):
        return packages.aptget.get(self.get_environment_type(), [])

    def is_installed(self):
        for pkg in self.get_packages():
            pkg_id = get_package_id(pkg)
            if not self.is_package_installed(pkg_id):
                return False
        return True

    def install(self):
        util.log_info("Installing AptGet packages")
        for pkg in self.get_packages():
            pkg_id = get_package_id(pkg)
            pkg_info = get_package_info(pkg)
            display_name = pkg_info["name"] if pkg_info["name"] != pkg_id else pkg_id
            if not self.install_package(pkg_id):
                util.log_error(f"Unable to install package {display_name}")
                return False
        return True

    def uninstall(self):
        util.log_info("Uninstalling AptGet packages")
        for pkg in self.get_packages():
            pkg_id = get_package_id(pkg)
            pkg_info = get_package_info(pkg)
            display_name = pkg_info["name"] if pkg_info["name"] != pkg_id else pkg_id
            if not self.uninstall_package(pkg_id):
                util.log_error(f"Unable to uninstall package {display_name}")
                return False
        return True

    def is_package_installed(self, package):
        output = self.connection.run_output([self.aptgetinstall_tool, "-s", package])
        return "Status: install ok installed" in output

    def update_package_lists(self):
        code = self.connection.run_blocking([self.aptget_tool, "update"], sudo = True)
        return code == 0

    def auto_remove_packages(self):
        code = self.connection.run_blocking([self.aptget_tool, "autoremove", "-y"], sudo = True)
        return code == 0

    def install_package(self, package):
        code = self.connection.run_blocking([self.aptget_tool, "install", "-y", package], sudo = True)
        return code == 0

    def uninstall_package(self, package):
        code = self.connection.run_blocking([self.aptget_tool, "remove", "-y", package], sudo = True)
        return code == 0
