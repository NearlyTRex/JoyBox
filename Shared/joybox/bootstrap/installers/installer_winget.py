# Local imports
from joybox.bootstrap import constants
from joybox.bootstrap import packages
from joybox import runoptions
from joybox import logger
from . import installer

# Installs the environment's winget package list by id
class WinGet(installer.Installer):
    def __init__(
        self,
        connection,
        flags = runoptions.RunFlags(),
        options = runoptions.RunOptions()):
        super().__init__(connection, flags, options)

    # Local Windows only
    def get_supported_environments(self):
        return [
            constants.EnvironmentType.LOCAL_WINDOWS,
        ]

    # The winget ids packages lists for this environment type
    def get_packages(self):
        return packages.winget.get(self.get_environment_type(), [])

    # Whether winget list finds every listed package
    def is_installed(self):
        for pkg in self.get_packages():
            if not self.is_package_installed(pkg):
                return False
        return True

    # The listed ids split into installed and missing
    def get_package_status(self):
        installed = []
        missing = []
        for pkg in self.get_packages():
            if self.is_package_installed(pkg):
                installed.append(pkg)
            else:
                missing.append(pkg)
        return {"installed": installed, "missing": missing}

    # winget install each listed id; False at the first failure
    def install(self):
        logger.log_info("Installing WinGet packages")
        for pkg in self.get_packages():
            if not self.install_package(pkg):
                logger.log_error(f"Unable to install package {pkg}")
                return False
        return True

    # winget uninstall each listed id; False at the first failure
    def uninstall(self):
        logger.log_info("Uninstalling WinGet packages")
        for pkg in self.get_packages():
            if not self.uninstall_package(pkg):
                logger.log_error(f"Unable to uninstall package {pkg}")
                return False
        return True

    # Whether winget list finds the exact id, as install and uninstall match it;
    # False on a nonzero exit
    def is_package_installed(self, package):
        code = self.connection.run_blocking([self.winget_tool, "list", "--id", package, "-e"])
        return code == 0

    # winget install one exact id silently, accepting the agreements; False on failure
    def install_package(self, package):
        code = self.connection.run_blocking([self.winget_tool, "install", "--accept-package-agreements", "--accept-source-agreements", "--id", package, "-e", "-h"])
        return code == 0

    # winget uninstall one exact id silently; False on failure
    def uninstall_package(self, package):
        code = self.connection.run_blocking([self.winget_tool, "uninstall", "--id", package, "-e", "-h"])
        return code == 0
