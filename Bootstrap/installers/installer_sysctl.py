# Imports
import os
import sys

# Local imports
import constants
from . import installer
from joybox import runoptions
from joybox import logger

# Sysctl settings to install
# Each setting has: key, value, description
SYSCTL_SETTINGS = [
    {
        "key": "fs.inotify.max_user_instances",
        "value": "1024",
        "description": "Raise inotify instance limit (GitKraken/editors exhaust the default 128 when switching repos)",
    },
]

# Sysctl
class Sysctl(installer.Installer):
    def __init__(
        self,
        connection,
        flags = runoptions.RunFlags(),
        options = runoptions.RunOptions()):
        super().__init__(connection, flags, options)

        # Path to the sysctl drop-in file
        self.conf_path = "/etc/sysctl.d/99-joybox.conf"

    def get_supported_environments(self):
        return [
            constants.EnvironmentType.LOCAL_UBUNTU,
            constants.EnvironmentType.REMOTE_UBUNTU,
        ]

    def _build_contents(self):
        lines = ["# Managed by JoyBox - do not edit by hand"]
        for setting in SYSCTL_SETTINGS:
            lines.append(f"# {setting['description']}")
            lines.append(f"{setting['key']} = {setting['value']}")
        return "\n".join(lines) + "\n"

    def is_installed(self):
        if not self.connection.does_file_or_directory_exist(self.conf_path):
            return False
        current = self.connection.read_file(self.conf_path, sudo=True)
        return current == self._build_contents()

    def install(self):

        # Start install
        logger.log_info("Installing sysctl settings")

        # Write the drop-in file
        for setting in SYSCTL_SETTINGS:
            logger.log_info(f"Setting {setting['key']} = {setting['value']}: {setting['description']}")
        success = self.connection.write_file(self.conf_path, self._build_contents(), sudo=True)
        if not success:
            logger.log_error(f"Failed to write {self.conf_path}")
            return False

        # Apply the settings
        logger.log_info("Applying sysctl settings")
        code = self.connection.run_blocking(["sysctl", "--system"], sudo=True)
        if code != 0:
            logger.log_error("Failed to apply sysctl settings")
            return False

        # All done
        logger.log_info("Sysctl settings installed successfully")
        return True

    def uninstall(self):

        # Start uninstall
        logger.log_info("Uninstalling sysctl settings")

        # Remove the drop-in file
        if self.connection.does_file_or_directory_exist(self.conf_path):
            logger.log_info(f"Removing {self.conf_path}")
            self.connection.remove_file_or_directory(self.conf_path, sudo=True)

            # Reload remaining settings (removed values revert on next reboot)
            logger.log_info("Reloading sysctl settings")
            self.connection.run_blocking(["sysctl", "--system"], sudo=True)

        # All done
        logger.log_info("Sysctl settings uninstalled")
        return True
