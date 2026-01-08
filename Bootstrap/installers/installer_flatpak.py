# Imports
import os
import sys

# Local imports
import util
import constants
import packages
from . import installer

# Extract package identifier from dict
def get_package_id(pkg):
    return pkg.get("id", pkg.get("name", ""))

# Get display info for a package
def get_package_info(pkg):
    pkg_id = get_package_id(pkg)
    return {
        "id": pkg_id,
        "repository": pkg.get("repository", "flathub"),
        "name": pkg.get("name", pkg_id) if pkg.get("id") else pkg_id,  # Use name for display if id exists
        "description": pkg.get("description", ""),
        "category": pkg.get("category", "")
    }

# Flatpak
class Flatpak(installer.Installer):
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
        return packages.flatpak.get(self.get_environment_type(), [])

    def is_installed(self):
        for pkg in self.get_packages():
            pkg_id = get_package_id(pkg)
            if not self.is_package_installed(pkg_id):
                return False
        return True

    def get_package_status(self):
        installed = []
        missing = []
        for pkg in self.get_packages():
            pkg_info = get_package_info(pkg)
            pkg_id = pkg_info["id"]
            display_name = pkg_info["name"]
            if self.is_package_installed(pkg_id):
                installed.append(display_name)
            else:
                missing.append(display_name)
        return {"installed": installed, "missing": missing}

    def install(self):
        util.log_info("Installing Flatpak packages")
        for pkg in self.get_packages():
            pkg_info = get_package_info(pkg)
            pkg_id = pkg_info["id"]
            pkg_repo = pkg_info["repository"]
            display_name = pkg_info["name"]
            if not self.install_package(pkg_repo, pkg_id):
                util.log_error(f"Unable to install package {display_name}")
                return False
        return True

    def uninstall(self):
        util.log_info("Uninstalling Flatpak packages")
        for pkg in self.get_packages():
            pkg_info = get_package_info(pkg)
            pkg_id = pkg_info["id"]
            display_name = pkg_info["name"]
            if not self.uninstall_package(pkg_id):
                util.log_error(f"Unable to uninstall package {display_name}")
                return False
        return True

    def is_package_installed(self, package):
        code = self.connection.run_blocking([self.flatpak_tool, "info", "--user", package])
        return code == 0

    def update_packages(self):
        code = self.connection.run_blocking([self.flatpak_tool, "update", "--user", "-y"])
        return code == 0

    def install_package(self, repository, package):
        code = self.connection.run_blocking([self.flatpak_tool, "install", "--user", "-y", repository, package])
        return code == 0

    def uninstall_package(self, package):
        code = self.connection.run_blocking([self.flatpak_tool, "uninstall", "--user", "-y", package])
        return code == 0
