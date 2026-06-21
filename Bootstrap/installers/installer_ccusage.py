# Imports
import os
import sys

# Local imports
import constants
from . import installer
from joybox import runoptions
from joybox import logger

# ccusage - Claude Code usage monitoring
class Ccusage(installer.Installer):
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

    def is_installed(self):
        code = self.connection.run_blocking(["npm", "list", "-g", "ccusage"])
        return code == 0

    def get_package_status(self):
        installed = []
        missing = []
        if self.is_installed():
            installed.append("ccusage")
        else:
            missing.append("ccusage")
        return {"installed": installed, "missing": missing}

    def install(self):

        # Start install
        logger.log_info("Installing ccusage")

        # Install via npm globally
        logger.log_info("Installing ccusage via npm")
        code = self.connection.run_blocking(
            ["npm", "install", "-g", "ccusage"],
            sudo=True
        )
        if code != 0:
            logger.log_error("Failed to install ccusage")
            return False

        # Verify installation
        logger.log_info("Verifying installation")
        if not self.is_installed():
            logger.log_error("ccusage installation verification failed")
            return False

        # All done
        logger.log_info("ccusage installed successfully")
        return True

    def uninstall(self):

        # Start uninstall
        logger.log_info("Uninstalling ccusage")

        # Remove via npm
        code = self.connection.run_blocking(
            ["npm", "uninstall", "-g", "ccusage"],
            sudo=True
        )
        if code != 0:
            logger.log_error("Failed to uninstall ccusage")
            return False

        # All done
        logger.log_info("ccusage uninstalled")
        return True
