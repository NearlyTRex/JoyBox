# Imports
import os
import sys

# Local imports
import constants
from . import installer
from joybox import runoptions
from joybox import logger

# GitKraken
class GitKraken(installer.Installer):
    def __init__(
        self,
        connection,
        flags = runoptions.RunFlags(),
        options = runoptions.RunOptions()):
        super().__init__(connection, flags, options)
        self.download_url = "https://release.gitkraken.com/linux/gitkraken-amd64.deb"
        self.deb_path = "/tmp/gitkraken-amd64.deb"

    def get_supported_environments(self):
        return [
            constants.EnvironmentType.LOCAL_UBUNTU,
        ]

    def is_installed(self):
        return self.connection.does_file_or_directory_exist("/usr/bin/gitkraken")

    def install(self):
        logger.log_info("Installing GitKraken")
        self.connection.download_file(self.download_url, self.deb_path)
        self.connection.run_checked([self.aptget_tool, "install", "-y", self.deb_path], sudo = True)
        self.connection.remove_file_or_directory(self.deb_path)
        return True

    def uninstall(self):
        logger.log_info("Uninstalling GitKraken")
        self.connection.run_checked([self.aptget_tool, "remove", "-y", "gitkraken"], sudo = True)
        return True
