# Imports
import os
import sys

# Local imports
import util
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

# Python
class Python(installer.Installer):
    def __init__(
        self,
        config,
        connection,
        flags = util.RunFlags(),
        options = util.RunOptions()):
        super().__init__(config, connection, flags, options)

    def get_packages(self):
        return packages.python.get(self.get_environment_type(), [])

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
            pkg_id = get_package_id(pkg)
            pkg_info = get_package_info(pkg)
            display_name = pkg_info["name"] if pkg_info["name"] != pkg_id else pkg_id
            if self.is_package_installed(pkg_id):
                installed.append(display_name)
            else:
                missing.append(display_name)
        return {"installed": installed, "missing": missing}

    def install(self):
        util.log_info("Installing Python packages")
        for pkg in self.get_packages():
            pkg_id = get_package_id(pkg)
            pkg_info = get_package_info(pkg)
            display_name = pkg_info["name"] if pkg_info["name"] != pkg_id else pkg_id
            if not self.install_package(pkg_id):
                util.log_error(f"Unable to install package {display_name}")
                return False
        return True

    def uninstall(self):
        util.log_info("Uninstalling Python packages")
        for pkg in self.get_packages():
            pkg_id = get_package_id(pkg)
            pkg_info = get_package_info(pkg)
            display_name = pkg_info["name"] if pkg_info["name"] != pkg_id else pkg_id
            if not self.uninstall_package(pkg_id):
                util.log_error(f"Unable to uninstall package {display_name}")
                return False
        return True

    def create_virtual_environment(self, venv_dir):
        code = self.connection.run_blocking([self.python_tool, "-m", "venv", venv_dir])
        return code == 0

    def is_package_installed(self, package):
        code = self.connection.run_blocking([self.python_venv_pip_tool, "show", package])
        return code == 0

    def install_package(self, package):
        code = self.connection.run_blocking([self.python_venv_pip_tool, "install", "--upgrade", package])
        return code == 0

    def uninstall_package(self, package):
        code = self.connection.run_blocking([self.python_venv_pip_tool, "uninstall", "-y", package])
        return code == 0
