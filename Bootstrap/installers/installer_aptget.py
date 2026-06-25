# Imports
import os
import sys

# Local imports
import constants
import packages
from . import installer
from joybox import runoptions
from joybox import logger

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
        connection,
        flags = runoptions.RunFlags(),
        options = runoptions.RunOptions()):
        super().__init__(connection, flags, options)

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
        logger.log_info("Installing AptGet packages")
        if not self.ensure_foreign_architectures():
            return False
        for pkg in self.get_packages():
            pkg_id = get_package_id(pkg)
            pkg_info = get_package_info(pkg)
            display_name = pkg_info["name"] if pkg_info["name"] != pkg_id else pkg_id
            if not self.install_package(pkg_id):
                logger.log_error(f"Unable to install package {display_name}")
                return False
        return True

    def uninstall(self):
        logger.log_info("Uninstalling AptGet packages")
        for pkg in self.get_packages():
            pkg_id = get_package_id(pkg)
            pkg_info = get_package_info(pkg)
            display_name = pkg_info["name"] if pkg_info["name"] != pkg_id else pkg_id
            if not self.uninstall_package(pkg_id):
                logger.log_error(f"Unable to uninstall package {display_name}")
                return False
        return True

    def ensure_foreign_architectures(self):
        architectures = []
        for pkg in self.get_packages():
            pkg_id = get_package_id(pkg)
            if ":" in pkg_id:
                arch = pkg_id.split(":", 1)[1]
                if arch and arch not in architectures:
                    architectures.append(arch)
        if not architectures:
            return True
        enabled = self.connection.run_output([self.aptgetinstall_tool, "--print-foreign-architectures"]).split()
        changed = False
        for arch in architectures:
            if arch in enabled:
                continue
            logger.log_info(f"Adding {arch} architecture")
            if self.connection.run_blocking([self.aptgetinstall_tool, "--add-architecture", arch], sudo = True) != 0:
                logger.log_error(f"Failed to add {arch} architecture")
                return False
            changed = True
        if changed:
            self.update_package_lists()
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

    def packages_removed_by_install(self, package):
        output = self.connection.run_output([
            self.aptget_tool, "install", "-s", package
        ])
        removed = []
        for line in output.splitlines():
            line = line.strip()
            if line.startswith("Remv "):
                parts = line.split()
                if len(parts) >= 2:
                    removed.append(parts[1])
        return removed

    def install_package(self, package):
        removed = self.packages_removed_by_install(package)
        if removed:
            logger.log_error(
                f"Refusing to install '{package}': apt would REMOVE "
                f"{len(removed)} package(s): {', '.join(removed)}. "
                f"Resolve the conflict manually (see the package's notes) "
                f"and re-run."
            )
            return False
        code = self.connection.run_blocking([
            "env", "DEBIAN_FRONTEND=noninteractive",
            self.aptget_tool, "install", "-y",
            "-o", "Dpkg::Options::=--force-confdef",
            "-o", "Dpkg::Options::=--force-confold",
            package
        ], sudo = True)
        return code == 0

    def uninstall_package(self, package):
        code = self.connection.run_blocking([self.aptget_tool, "remove", "-y", package], sudo = True)
        return code == 0
