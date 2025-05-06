# Imports
import os
import sys

# Local imports
import util
import tools
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
        self.aptget_tool = tools.GetAptGetTool(self.config)
        self.aptgetinstall_tool = tools.GetAptGetInstallTool(self.config)

    def IsInstalled(self):
        return self.connection.DoesFileOrDirectoryExist("/usr/bin/google-chrome")

    def Install(self):
        util.LogInfo("Installing Chrome")
        self.connection.DownloadFile(f"{self.url}/google-chrome-stable_current_amd64.deb", "/tmp/google-chrome.deb")
        self.connection.RunChecked([self.aptgetinstall_tool, "-i", "/tmp/google-chrome.deb"], sudo = True)
        self.connection.RemoveFileOrDirectory("/tmp/google-chrome.deb")
        return True

    def Uninstall(self):
        util.LogInfo("Uninstalling Chrome")
        self.connection.RunChecked([self.aptget_tool, "remove", "-y", "google-chrome-stable"], sudo = True)
        self.connection.RemoveFileOrDirectory(self.sources_list_path, sudo = True)
        self.connection.RemoveFileOrDirectory(self.archive_key_path, sudo = True)
        return False
