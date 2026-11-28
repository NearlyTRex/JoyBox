# Local imports
from joybox.bootstrap import constants
from joybox.bootstrap import packages
from joybox import runoptions
from joybox import logger
from . import installer

# Extract package identifier from dict
def get_flatpak_package_id(pkg):
    return pkg.get("id", pkg.get("name", ""))

# Get display info for a package
def get_flatpak_package_info(pkg):
    pkg_id = get_flatpak_package_id(pkg)
    return {
        "id": pkg_id,
        "repository": pkg.get("repository", "flathub"),
        "name": pkg.get("name", pkg_id) if pkg.get("id") else pkg_id,  # Use name for display if id exists
        "description": pkg.get("description", ""),
        "category": pkg.get("category", "")
    }

# Installs the environment's flatpak list for the user, from flathub unless an entry names a remote
class Flatpak(installer.Installer):
    def __init__(
        self,
        connection,
        flags = runoptions.RunFlags(),
        options = runoptions.RunOptions()):
        super().__init__(connection, flags, options)

    # Local and remote Ubuntu
    def get_supported_environments(self):
        return [
            constants.EnvironmentType.LOCAL_UBUNTU,
            constants.EnvironmentType.REMOTE_UBUNTU,
        ]

    # The flatpak entries packages lists for this environment type
    def get_packages(self):
        return packages.flatpak.get(self.get_environment_type(), [])

    # Whether flatpak info finds every listed app in the user installation
    def is_installed(self):
        for pkg in self.get_packages():
            pkg_id = get_flatpak_package_id(pkg)
            if not self.is_package_installed(pkg_id):
                return False
        return True

    # The listed apps split into installed and missing display names
    def get_package_status(self):
        installed = []
        missing = []
        for pkg in self.get_packages():
            pkg_info = get_flatpak_package_info(pkg)
            pkg_id = pkg_info["id"]
            display_name = pkg_info["name"]
            if self.is_package_installed(pkg_id):
                installed.append(display_name)
            else:
                missing.append(display_name)
        return {"installed": installed, "missing": missing}

    # Add the flathub remote for the user when it is missing; False on failure
    def ensure_flathub_remote(self):
        logger.log_info("Ensuring flathub remote is configured")
        code = self.connection.run_blocking([
            self.flatpak_tool, "remote-add", "--user", "--if-not-exists",
            "flathub", "https://dl.flathub.org/repo/flathub.flatpakrepo"
        ])
        return code == 0

    # Add flathub, then install each listed app for the user; False at the first failure
    def install(self):
        logger.log_info("Installing Flatpak packages")
        if not self.ensure_flathub_remote():
            logger.log_error("Failed to configure flathub remote")
            return False
        for pkg in self.get_packages():
            pkg_info = get_flatpak_package_info(pkg)
            pkg_id = pkg_info["id"]
            pkg_repo = pkg_info["repository"]
            display_name = pkg_info["name"]
            if not self.install_package(pkg_repo, pkg_id):
                logger.log_error(f"Unable to install package {display_name}")
                return False
        return True

    # Uninstall each listed app for the user; False at the first failure
    def uninstall(self):
        logger.log_info("Uninstalling Flatpak packages")
        for pkg in self.get_packages():
            pkg_info = get_flatpak_package_info(pkg)
            pkg_id = pkg_info["id"]
            display_name = pkg_info["name"]
            if not self.uninstall_package(pkg_id):
                logger.log_error(f"Unable to uninstall package {display_name}")
                return False
        return True

    # Whether flatpak info finds the app in the user installation
    def is_package_installed(self, package):
        code = self.connection.run_blocking([self.flatpak_tool, "info", "--user", package])
        return code == 0

    # Update every user-installed flatpak; False on a nonzero exit
    def update_packages(self):
        code = self.connection.run_blocking([self.flatpak_tool, "update", "--user", "-y"])
        return code == 0

    # Install one app for the user from the given remote; False on a nonzero exit
    def install_package(self, repository, package):
        code = self.connection.run_blocking([self.flatpak_tool, "install", "--user", "-y", repository, package])
        return code == 0

    # Uninstall one app from the user installation; False on a nonzero exit
    def uninstall_package(self, package):
        code = self.connection.run_blocking([self.flatpak_tool, "uninstall", "--user", "-y", package])
        return code == 0
