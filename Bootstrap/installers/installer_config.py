# Imports
import os
import sys

# Local imports
import constants
from joybox import default_settings
from . import installer
from joybox import runoptions
from joybox import logger

# Config
class Config(installer.Installer):
    def __init__(
        self,
        connection,
        flags = runoptions.RunFlags(),
        options = runoptions.RunOptions()):
        super().__init__(connection, flags, options)

        # Path to config file
        self.config_path = os.path.expandvars("$HOME/JoyBox.ini")

        # Minimal sections to include by default
        self.minimal_sections = [
            "UserData.Dirs",
            "UserData.Protection",
            "Tools.Python",
            "Tools.Git",
        ]

    def generate_config_content(self, sections=None, full=False):
        target_sections = None if full else (sections if sections else self.minimal_sections)
        return default_settings.generate_default_config_content(sections=target_sections)

    def get_supported_environments(self):
        return [
            constants.EnvironmentType.LOCAL_UBUNTU,
            constants.EnvironmentType.LOCAL_WINDOWS,
            constants.EnvironmentType.REMOTE_UBUNTU,
            constants.EnvironmentType.REMOTE_WINDOWS,
        ]

    def is_installed(self):
        return self.connection.does_file_or_directory_exist(self.config_path)

    def install(self):

        # Start install
        logger.log_info("Installing JoyBox configuration file")

        # Check if config already exists
        if self.connection.does_file_or_directory_exist(self.config_path):
            logger.log_info("JoyBox.ini already exists, skipping (will not overwrite)")
            return True

        # Generate config content (minimal by default)
        logger.log_info("Generating minimal JoyBox.ini template")
        config_content = self.generate_config_content(full=False)

        # Write config file
        logger.log_info(f"Writing {self.config_path}")
        if self.connection.write_file(self.config_path, config_content):
            logger.log_info("JoyBox.ini created successfully")
            logger.log_info("Edit ~/JoyBox.ini to configure your installation")
            return True

        # Configuration failed
        logger.log_info("Configuration file installation failed")
        return False

    def install_full(self):

        # Start install
        logger.log_info("Installing full JoyBox configuration file")

        # Check if config already exists
        if self.connection.does_file_or_directory_exist(self.config_path):
            logger.log_info("JoyBox.ini already exists, skipping")
            return True

        # Generate config content
        config_content = self.generate_config_content(full=True)
        if self.connection.write_file(self.config_path, config_content):
            logger.log_info("Full JoyBox.ini created successfully")
            return True

        # Configuration failed
        logger.log_info("Configuration file installation failed")
        return False

    def uninstall(self):

        # Start uninstall
        logger.log_info("Uninstalling JoyBox configuration file")

        # Backup before removing
        if self.connection.does_file_or_directory_exist(self.config_path):
            backup_path = os.path.expandvars("$HOME/JoyBox.ini.backup")
            logger.log_info(f"Backing up to {backup_path}")
            self.connection.copy_file_or_directory(self.config_path, backup_path)
            self.connection.remove_file_or_directory(self.config_path)

        # All done
        logger.log_info("Configuration file uninstallation complete")
        return True
