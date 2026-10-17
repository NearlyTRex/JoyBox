# Imports
import os

# Local imports
import joybox.bootstrap.constants as constants
import joybox.desktopentry as desktopentry
from . import installer
from joybox import runoptions
from joybox import logger
from joybox import settings

# Desktop autostart entries to install
# Each entry has: filename, name, description, the JoyBox command it runs, and
# the setting that turns it on, so each machine starts only its own role.
# XDG autostart runs inside the desktop session, which the streaming programs
# need for its display; Cinnamon does not start graphical-session.target.
AUTOSTART_ENTRIES = [
    {
        "filename": "joybox-sunshine.desktop",
        "name": "Sunshine",
        "description": "Stream this machine's games to Moonlight clients",
        "command": "launch_sunshine",
        "enabled_by": ("Tools.Sunshine", "sunshine_streaming_host"),
    },
    {
        "filename": "joybox-moonlight.desktop",
        "name": "Moonlight",
        "description": "Stream games from the Sunshine host",
        "command": "launch_moonlight",
        "enabled_by": ("Tools.Moonlight", "moonlight_autostart"),
    },
]

# Autostart
class Autostart(installer.Installer):
    def __init__(
        self,
        connection,
        flags = runoptions.RunFlags(),
        options = runoptions.RunOptions()):
        super().__init__(connection, flags, options)

        # Path to the user's autostart directory
        self.autostart_dir = os.path.join(os.path.expanduser("~"), ".config", "autostart")

    def get_supported_environments(self):
        return [
            constants.EnvironmentType.LOCAL_UBUNTU,
        ]

    def get_entry_path(self, entry):
        return os.path.join(self.autostart_dir, entry["filename"])

    def is_entry_enabled(self, entry):
        return settings.get_bool_value(*entry["enabled_by"], default_value = False, throw_exception = False)

    def build_entry(self, entry):
        return desktopentry.build_desktop_entry(
            entry["name"], entry["description"], entry["command"], ["X-GNOME-Autostart-enabled=true"])

    def is_installed(self):
        for entry in AUTOSTART_ENTRIES:
            exists = self.connection.does_file_or_directory_exist(self.get_entry_path(entry))
            if exists != self.is_entry_enabled(entry):
                return False
        return True

    def install(self):

        # Start install
        logger.log_info("Installing autostart entries")
        self.connection.make_directory(self.autostart_dir)

        # Write the enabled entries and drop the ones turned off
        for entry in AUTOSTART_ENTRIES:
            entry_path = self.get_entry_path(entry)
            if not self.is_entry_enabled(entry):
                if self.connection.does_file_or_directory_exist(entry_path):
                    logger.log_info(f"Removing {entry['filename']}, which is turned off for this machine")
                    self.connection.remove_file_or_directory(entry_path)
                continue
            logger.log_info(f"Installing {entry['filename']}: {entry['description']}")
            if not self.connection.write_file(entry_path, self.build_entry(entry)):
                logger.log_error(f"Failed to write {entry_path}")
                return False

        # All done
        logger.log_info("Autostart entries installed")
        return True

    def uninstall(self):

        # Start uninstall
        logger.log_info("Uninstalling autostart entries")

        # Remove each entry
        for entry in AUTOSTART_ENTRIES:
            entry_path = self.get_entry_path(entry)
            if self.connection.does_file_or_directory_exist(entry_path):
                logger.log_info(f"Removing {entry['filename']}")
                self.connection.remove_file_or_directory(entry_path)

        # All done
        logger.log_info("Autostart entries uninstalled")
        return True
