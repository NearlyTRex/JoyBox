# Imports
import os
import sys

# Local imports
import util
import constants
from . import installer

# OnePassword
class OnePassword(installer.Installer):
    def __init__(
        self,
        config,
        connection,
        flags = util.RunFlags(),
        options = util.RunOptions()):
        super().__init__(config, connection, flags, options)
        self.url = f"https://downloads.1password.com"
        self.archive_key = "1password-archive-keyring.gpg"
        self.sources_list = "1password.list"
        self.policy = "AC2D62742012EA22"
        self.archive_key_path = f"/usr/share/keyrings/{self.archive_key}"
        self.sources_list_path = f"/etc/apt/sources.list.d/{self.sources_list}"
        self.policy_path = f"/etc/debsig/policies/{self.policy}/"
        self.policy_keyring_path = f"/usr/share/debsig/keyrings/{self.policy}"

    def get_supported_environments(self):
        return [
            constants.EnvironmentType.LOCAL_UBUNTU,
        ]

    def is_installed(self):
        return self.connection.does_file_or_directory_exist("/usr/bin/1password")

    def install(self):
        util.log_info("Installing 1Password")
        self.connection.make_directory(self.policy_path, sudo = True)
        self.connection.make_directory(self.policy_keyring_path, sudo = True)
        self.connection.download_file(f"{self.url}/linux/keys/1password.asc", "/tmp/1password.asc")
        self.connection.download_file(f"{self.url}/linux/debian/debsig/1password.pol", f"{self.policy_path}/1password.pol", sudo = True)
        self.connection.run_checked([self.gpg_tool, "--dearmor", "-o", self.archive_key_path, "/tmp/1password.asc"], sudo = True)
        self.connection.run_checked([self.gpg_tool, "--dearmor", "-o", f"{self.policy_keyring_path}/debsig.gpg", "/tmp/1password.asc"], sudo = True)
        self.connection.write_file(self.sources_list_path, f"deb [arch=amd64 signed-by={self.archive_key_path}] {self.url}/linux/debian/amd64 stable main\n")
        self.connection.run_checked([self.aptget_tool, "update"], sudo = True)
        self.connection.run_checked([self.aptget_tool, "install", "-y", "1password"], sudo = True)
        return True

    def uninstall(self):
        util.log_info("Uninstalling 1Password")
        self.connection.run_checked([self.aptget_tool, "remove", "-y", "1password"], sudo = True)
        self.connection.remove_file_or_directory(self.sources_list_path, sudo = True)
        self.connection.remove_file_or_directory(self.archive_key_path, sudo = True)
        self.connection.remove_file_or_directory(self.policy_path, sudo = True)
        self.connection.remove_file_or_directory(self.policy_keyring_path, sudo = True)
        return True
