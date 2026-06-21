# Imports
import os
import sys

# Local imports
import constants
from . import installer
from joybox import runoptions
from joybox import logger

# Udev rules to install
# Each rule has: filename, description, content
UDEV_RULES = [
    {
        "filename": "99-asrock-led-no-joystick.rules",
        "description": "Prevent ASRock LED Controller from registering as joystick",
        "content": 'SUBSYSTEM=="input", ATTRS{idVendor}=="26ce", ATTRS{idProduct}=="01a2", ENV{ID_INPUT_JOYSTICK}="", RUN+="/bin/rm -f /dev/input/js0"',
    },
]

# Udev
class Udev(installer.Installer):
    def __init__(
        self,
        connection,
        flags = runoptions.RunFlags(),
        options = runoptions.RunOptions()):
        super().__init__(connection, flags, options)

        # Path to udev rules directory
        self.rules_dir = "/etc/udev/rules.d"

    def get_supported_environments(self):
        return [
            constants.EnvironmentType.LOCAL_UBUNTU,
            constants.EnvironmentType.REMOTE_UBUNTU,
        ]

    def _get_rule_path(self, rule):
        return os.path.join(self.rules_dir, rule["filename"])

    def is_installed(self):
        for rule in UDEV_RULES:
            rule_path = self._get_rule_path(rule)
            if not self.connection.does_file_or_directory_exist(rule_path):
                return False
        return True

    def install(self):

        # Start install
        logger.log_info("Installing udev rules")

        # Install each rule
        for rule in UDEV_RULES:
            rule_path = self._get_rule_path(rule)

            # Check if rule already exists
            if self.connection.does_file_or_directory_exist(rule_path):
                logger.log_info(f"Rule {rule['filename']} already exists, skipping")
                continue

            # Write rule file
            logger.log_info(f"Installing {rule['filename']}: {rule['description']}")
            success = self.connection.write_file(rule_path, rule['content'] + '\n', sudo=True)
            if not success:
                logger.log_error(f"Failed to install {rule['filename']}")
                return False

        # Reload udev rules
        logger.log_info("Reloading udev rules")
        code = self.connection.run_blocking(["udevadm", "control", "--reload-rules"], sudo=True)
        if code != 0:
            logger.log_error("Failed to reload udev rules")
            return False
        code = self.connection.run_blocking(["udevadm", "trigger"], sudo=True)
        if code != 0:
            logger.log_error("Failed to trigger udev rules")
            return False

        # All done
        logger.log_info("Udev rules installed successfully")
        return True

    def uninstall(self):

        # Start uninstall
        logger.log_info("Uninstalling udev rules")

        # Remove each rule
        for rule in UDEV_RULES:
            rule_path = self._get_rule_path(rule)

            if self.connection.does_file_or_directory_exist(rule_path):
                logger.log_info(f"Removing {rule['filename']}")
                self.connection.remove_file_or_directory(rule_path, sudo=True)

        # Reload udev rules
        logger.log_info("Reloading udev rules")
        self.connection.run_blocking(["udevadm", "control", "--reload-rules"], sudo=True)
        self.connection.run_blocking(["udevadm", "trigger"], sudo=True)

        # All done
        logger.log_info("Udev rules uninstalled")
        return True
