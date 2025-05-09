# Imports
import os
import sys

# Local imports
import util
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

    def IsInstalled(self):
        return self.connection.DoesFileOrDirectoryExist("/usr/bin/1password")

    def Install(self):
        util.LogInfo("Installing 1Password")
        self.connection.MakeDirectory(self.policy_path, sudo = True)
        self.connection.MakeDirectory(self.policy_keyring_path, sudo = True)
        self.connection.DownloadFile(f"{self.url}/linux/keys/1password.asc", "/tmp/1password.asc")
        self.connection.DownloadFile(f"{self.url}/linux/debian/debsig/1password.pol", f"{self.policy_path}/1password.pol", sudo = True)
        self.connection.RunChecked([self.gpg_tool, "--dearmor", "-o", self.archive_key_path, "/tmp/1password.asc"], sudo = True)
        self.connection.RunChecked([self.gpg_tool, "--dearmor", "-o", f"{self.policy_keyring_path}/debsig.gpg", "/tmp/1password.asc"], sudo = True)
        self.connection.WriteFile(self.sources_list_path, f"deb [arch=amd64 signed-by={self.archive_key_path}] {self.url}/linux/debian/amd64 stable main\n")
        self.connection.RunChecked([self.aptget_tool, "update"], sudo = True)
        self.connection.RunChecked([self.aptget_tool, "install", "-y", "1password"], sudo = True)
        return True

    def Uninstall(self):
        util.LogInfo("Uninstalling 1Password")
        self.connection.RunChecked([self.aptget_tool, "remove", "-y", "1password"], sudo = True)
        self.connection.RemoveFileOrDirectory(self.sources_list_path, sudo = True)
        self.connection.RemoveFileOrDirectory(self.archive_key_path, sudo = True)
        self.connection.RemoveFileOrDirectory(self.policy_path, sudo = True)
        self.connection.RemoveFileOrDirectory(self.policy_keyring_path, sudo = True)
        return True
