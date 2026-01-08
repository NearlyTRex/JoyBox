# Imports
import os
import sys

# Local imports
import util
import constants
from . import installer

# Wine
class Wine(installer.Installer):
    def __init__(
        self,
        config,
        connection,
        flags = util.RunFlags(),
        options = util.RunOptions()):
        super().__init__(config, connection, flags, options)
        self.codename = util.get_ubuntu_codename()
        self.url = "https://dl.winehq.org/wine-builds"
        self.archive_key = "winehq-archive.key"
        self.sources_list = f"winehq-{self.codename}.sources"
        self.archive_key_path = f"/etc/apt/keyrings/{self.archive_key}"
        self.sources_list_path = f"/etc/apt/sources.list.d/{self.sources_list}"

    def get_supported_environments(self):
        return [
            constants.EnvironmentType.LOCAL_UBUNTU,
        ]

    def is_installed(self):
        return self.connection.does_file_or_directory_exist("/usr/bin/wine")

    def install(self):
        util.log_info("Installing Wine")
        self.connection.run_checked([self.aptgetinstall_tool, "--add-architecture", "i386"], sudo = True)
        self.connection.download_file(f"{self.url}/winehq.key", self.archive_key_path, sudo = True)
        self.connection.download_file(f"{self.url}/ubuntu/dists/{self.codename}/{self.sources_list}", self.sources_list_path, sudo = True)
        self.connection.run_checked([self.aptget_tool, "update"], sudo = True)
        self.connection.run_checked([self.aptget_tool, "install", "-y", "winehq-devel"], sudo = True)
        self.connection.run_checked([self.aptget_tool, "install", "-y", "winetricks"], sudo = True)
        return True

    def uninstall(self):
        util.log_info("Uninstalling Wine")
        self.connection.run_checked([self.aptget_tool, "remove", "-y", "winehq-devel"], sudo = True)
        self.connection.run_checked([self.aptget_tool, "remove", "-y", "winetricks"], sudo = True)
        self.connection.remove_file_or_directory(self.sources_list_path, sudo = True)
        self.connection.remove_file_or_directory(self.archive_key_path, sudo = True)
        return True
