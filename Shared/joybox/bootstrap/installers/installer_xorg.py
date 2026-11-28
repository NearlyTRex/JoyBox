# Imports
import os

# Local imports
from joybox.bootstrap import constants
from joybox import runoptions
from joybox import logger
from . import installer

# Xorg InputClass snippets to install
# Each input class has: identifier, description, options (a list of MatchX / Option lines)
INPUT_CLASSES = [
    {
        "identifier": "JoyBox Apple Magic Trackpad No Middle Button",
        "description": "Remap the Magic Trackpad middle-click zone to left-click",
        "options": [
            'MatchProduct "Apple Inc. Magic Trackpad"',
            'MatchIsTouchpad "on"',
            'Option "ButtonMapping" "1 1 3 4 5 6 7"',
        ],
    },
]

# Writes the Xorg InputClass sections in INPUT_CLASSES to a drop-in in /etc/X11/xorg.conf.d
class Xorg(installer.Installer):
    def __init__(
        self,
        connection,
        flags = runoptions.RunFlags(),
        options = runoptions.RunOptions()):
        super().__init__(connection, flags, options)

        # Path to the Xorg input configuration drop-in
        self.conf_path = "/etc/X11/xorg.conf.d/99-joybox-input.conf"

    # Local Ubuntu only
    def get_supported_environments(self):
        return [
            constants.EnvironmentType.LOCAL_UBUNTU,
        ]

    # The drop-in text: one InputClass section per entry, each under its description
    def build_contents(self):
        lines = ["# Managed by JoyBox - do not edit by hand"]
        for input_class in INPUT_CLASSES:
            lines.append("")
            lines.append(f"# {input_class['description']}")
            lines.append('Section "InputClass"')
            lines.append(f'    Identifier "{input_class["identifier"]}"')
            for option in input_class["options"]:
                lines.append(f"    {option}")
            lines.append("EndSection")
        return "\n".join(lines) + "\n"

    # Whether the drop-in exists and matches what the entries would write
    def is_installed(self):
        if not self.connection.does_file_or_directory_exist(self.conf_path):
            return False
        current = self.connection.read_file(self.conf_path, sudo=True)
        return current == self.build_contents()

    # Create xorg.conf.d and write the drop-in as root; it applies at the next X start
    def install(self):

        # Start install
        logger.log_info("Installing Xorg input configuration")

        # Ensure the directory exists
        code = self.connection.run_blocking(
            ["install", "-d", "-m", "0755", os.path.dirname(self.conf_path)], sudo=True)
        if code != 0:
            logger.log_error(f"Failed to create {os.path.dirname(self.conf_path)}")
            return False

        # Write the configuration file
        for input_class in INPUT_CLASSES:
            logger.log_info(f"Installing input rule: {input_class['description']}")
        success = self.connection.write_file(self.conf_path, self.build_contents(), sudo=True)
        if not success:
            logger.log_error(f"Failed to write {self.conf_path}")
            return False

        # All done (takes effect at the next X server start / login)
        logger.log_info("Xorg input configuration installed successfully")
        logger.log_info("Log out and back in (or reboot) for it to take effect")
        return True

    # Delete the drop-in
    def uninstall(self):

        # Start uninstall
        logger.log_info("Uninstalling Xorg input configuration")

        # Remove the drop-in
        if self.connection.does_file_or_directory_exist(self.conf_path):
            logger.log_info(f"Removing {self.conf_path}")
            self.connection.remove_file_or_directory(self.conf_path, sudo=True)

        # All done
        logger.log_info("Xorg input configuration uninstalled")
        return True
