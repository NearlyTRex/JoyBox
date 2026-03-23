# Imports
import os
import sys

# Local imports
import util
import constants
from . import installer

# ccusage - Claude Code usage monitoring
class Ccusage(installer.Installer):
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
        util.log_info("Installing ccusage")

        # Install via npm globally
        util.log_info("Installing ccusage via npm")
        code = self.connection.run_blocking(
            ["npm", "install", "-g", "ccusage"],
            sudo=True
        )
        if code != 0:
            util.log_error("Failed to install ccusage")
            return False

        # Verify installation
        util.log_info("Verifying installation")
        if not self.is_installed():
            util.log_error("ccusage installation verification failed")
            return False

        # All done
        util.log_info("ccusage installed successfully")
        return True

    def uninstall(self):

        # Start uninstall
        util.log_info("Uninstalling ccusage")

        # Remove via npm
        code = self.connection.run_blocking(
            ["npm", "uninstall", "-g", "ccusage"],
            sudo=True
        )
        if code != 0:
            util.log_error("Failed to uninstall ccusage")
            return False

        # All done
        util.log_info("ccusage uninstalled")
        return True
