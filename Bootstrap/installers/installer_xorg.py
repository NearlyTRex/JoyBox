# Imports
import os
import sys

# Local imports
import util
import constants
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

# Xorg
class Xorg(installer.Installer):
    def __init__(
        self,
        config,
        connection,
        flags = util.RunFlags(),
        options = util.RunOptions()):
        super().__init__(config, connection, flags, options)

        # Path to the Xorg input configuration drop-in
        self.conf_path = "/etc/X11/xorg.conf.d/99-joybox-input.conf"

    def get_supported_environments(self):
        return [
            constants.EnvironmentType.LOCAL_UBUNTU,
        ]

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

    def is_installed(self):
        if not self.connection.does_file_or_directory_exist(self.conf_path):
            return False
        current = self.connection.read_file(self.conf_path, sudo=True)
        return current == self.build_contents()

    def install(self):

        # Start install
        util.log_info("Installing Xorg input configuration")

        # Ensure the directory exists
        code = self.connection.run_blocking(
            ["install", "-d", "-m", "0755", os.path.dirname(self.conf_path)], sudo=True)
        if code != 0:
            util.log_error(f"Failed to create {os.path.dirname(self.conf_path)}")
            return False

        # Write the configuration file
        for input_class in INPUT_CLASSES:
            util.log_info(f"Installing input rule: {input_class['description']}")
        success = self.connection.write_file(self.conf_path, self.build_contents(), sudo=True)
        if not success:
            util.log_error(f"Failed to write {self.conf_path}")
            return False

        # All done (takes effect at the next X server start / login)
        util.log_info("Xorg input configuration installed successfully")
        util.log_info("Log out and back in (or reboot) for it to take effect")
        return True

    def uninstall(self):

        # Start uninstall
        util.log_info("Uninstalling Xorg input configuration")

        # Remove the drop-in
        if self.connection.does_file_or_directory_exist(self.conf_path):
            util.log_info(f"Removing {self.conf_path}")
            self.connection.remove_file_or_directory(self.conf_path, sudo=True)

        # All done
        util.log_info("Xorg input configuration uninstalled")
        return True
