# Imports
import os
import sys

# Local imports
import util
import constants
from . import installer

# Brave
class Brave(installer.Installer):
    def __init__(
        self,
        config,
        connection,
        flags = util.RunFlags(),
        options = util.RunOptions()):
        super().__init__(config, connection, flags, options)
        self.url = "https://brave-browser-apt-release.s3.brave.com"
        self.archive_key = "brave-browser-archive-keyring.gpg"
        self.sources_list = "brave-browser-release.list"
        self.archive_key_path = f"/usr/share/keyrings/{self.archive_key}"
        self.sources_list_path = f"/etc/apt/sources.list.d/{self.sources_list}"

    def get_supported_environments(self):
        return [
            constants.EnvironmentType.LOCAL_UBUNTU,
        ]

    def is_installed(self):
        return self.connection.does_file_or_directory_exist("/usr/bin/brave-browser")

    def install(self):
        util.log_info("Installing Brave")
        self.connection.download_file(f"{self.url}/{self.archive_key}", self.archive_key_path, sudo = True)
        self.connection.write_file(f"/tmp/{self.sources_list}", f"deb [signed-by={self.archive_key_path}] {self.url}/ stable main\n")
        self.connection.move_file_or_directory(f"/tmp/{self.sources_list}", self.sources_list_path, sudo = True)
        self.connection.run_checked([self.aptget_tool, "update"], sudo = True)
        self.connection.run_checked([self.aptget_tool, "install", "-y", "brave-browser"], sudo = True)
        return True

    def uninstall(self):
        util.log_info("Uninstalling Brave")
        self.connection.run_checked([self.aptget_tool, "remove", "-y", "brave-browser"], sudo = True)
        self.connection.remove_file_or_directory(self.sources_list_path, sudo = True)
        self.connection.remove_file_or_directory(self.archive_key_path, sudo = True)
        return False
