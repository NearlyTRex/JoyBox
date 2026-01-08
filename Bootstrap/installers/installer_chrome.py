# Imports
import os
import sys

# Local imports
import util
import constants
from . import installer

# Chrome
class Chrome(installer.Installer):
    def __init__(
        self,
        config,
        connection,
        flags = util.RunFlags(),
        options = util.RunOptions()):
        super().__init__(config, connection, flags, options)
        self.url = "https://dl.google.com/linux/direct"
        self.archive_key = "google-chrome.gpg"
        self.sources_list = "google-chrome.list"
        self.archive_key_path = f"/etc/apt/trusted.gpg.d/{self.archive_key}"
        self.sources_list_path = f"/etc/apt/sources.list.d/{self.sources_list}"

    def get_supported_environments(self):
        return [
            constants.EnvironmentType.LOCAL_UBUNTU,
        ]

    def is_installed(self):
        return self.connection.does_file_or_directory_exist("/usr/bin/google-chrome")

    def install(self):
        util.log_info("Installing Chrome")
        self.connection.download_file(f"{self.url}/google-chrome-stable_current_amd64.deb", "/tmp/google-chrome.deb")
        self.connection.run_checked([self.aptgetinstall_tool, "-i", "/tmp/google-chrome.deb"], sudo = True)
        self.connection.remove_file_or_directory("/tmp/google-chrome.deb")
        return True

    def uninstall(self):
        util.log_info("Uninstalling Chrome")
        self.connection.run_checked([self.aptget_tool, "remove", "-y", "google-chrome-stable"], sudo = True)
        self.connection.remove_file_or_directory(self.sources_list_path, sudo = True)
        self.connection.remove_file_or_directory(self.archive_key_path, sudo = True)
        return False
