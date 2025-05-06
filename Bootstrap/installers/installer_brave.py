# Imports
import os
import sys

# Local imports
import util
import tools
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
        self.aptget_tool = tools.GetAptGetTool(self.config)

    def IsInstalled(self):
        return self.connection.DoesFileOrDirectoryExist("/usr/bin/brave-browser")

    def Install(self):
        util.LogInfo("Installing Brave")
        self.connection.DownloadFile(f"{self.url}/{self.archive_key}", self.archive_key_path, sudo = True)
        self.connection.WriteFile(f"/tmp/{self.sources_list}", f"deb [signed-by={self.archive_key_path}] {self.url}/ stable main\n")
        self.connection.MoveFileOrDirectory(f"/tmp/{self.sources_list}", self.sources_list_path, sudo = True)
        self.connection.RunChecked([self.aptget_tool, "update"], sudo = True)
        self.connection.RunChecked([self.aptget_tool, "install", "-y", "brave-browser"], sudo = True)
        return True

    def Uninstall(self):
        util.LogInfo("Uninstalling Brave")
        self.connection.RunChecked([self.aptget_tool, "remove", "-y", "brave-browser"], sudo = True)
        self.connection.RemoveFileOrDirectory(self.sources_list_path, sudo = True)
        self.connection.RemoveFileOrDirectory(self.archive_key_path, sudo = True)
        return False
