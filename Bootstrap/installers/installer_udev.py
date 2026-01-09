# Imports
import os
import sys

# Local imports
import util
import constants
from . import installer

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
        config,
        connection,
        flags = util.RunFlags(),
        options = util.RunOptions()):
        super().__init__(config, connection, flags, options)

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
        # Check if all rules are installed
        for rule in UDEV_RULES:
            rule_path = self._get_rule_path(rule)
            if not self.connection.does_file_or_directory_exist(rule_path):
                return False
        return True

    def install(self):

        # Start install
        util.log_info("Installing udev rules")

        # Install each rule
        for rule in UDEV_RULES:
            rule_path = self._get_rule_path(rule)

            # Check if rule already exists
            if self.connection.does_file_or_directory_exist(rule_path):
                util.log_info(f"Rule {rule['filename']} already exists, skipping")
                continue

            # Write rule file
            util.log_info(f"Installing {rule['filename']}: {rule['description']}")
            cmd = f"echo '{rule['content']}' | sudo tee {rule_path}"
            result = self.connection.run_command(cmd)
            if result.return_code != 0:
                util.log_error(f"Failed to install {rule['filename']}")
                return False

        # Reload udev rules
        util.log_info("Reloading udev rules")
        result = self.connection.run_command("sudo udevadm control --reload-rules && sudo udevadm trigger")
        if result.return_code != 0:
            util.log_error("Failed to reload udev rules")
            return False

        # All done
        util.log_info("Udev rules installed successfully")
        return True

    def uninstall(self):

        # Start uninstall
        util.log_info("Uninstalling udev rules")

        # Remove each rule
        for rule in UDEV_RULES:
            rule_path = self._get_rule_path(rule)

            if self.connection.does_file_or_directory_exist(rule_path):
                util.log_info(f"Removing {rule['filename']}")
                result = self.connection.run_command(f"sudo rm -f {rule_path}")
                if result.return_code != 0:
                    util.log_error(f"Failed to remove {rule['filename']}")

        # Reload udev rules
        util.log_info("Reloading udev rules")
        self.connection.run_command("sudo udevadm control --reload-rules && sudo udevadm trigger")

        # All done
        util.log_info("Udev rules uninstalled")
        return True
