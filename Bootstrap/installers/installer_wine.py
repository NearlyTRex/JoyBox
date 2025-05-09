# Imports
import os
import sys

# Local imports
import util
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
        self.codename = util.GetUbuntuCodename()
        self.url = "https://dl.winehq.org/wine-builds"
        self.archive_key = "winehq-archive.key"
        self.sources_list = f"winehq-{self.codename}.sources"
        self.archive_key_path = f"/etc/apt/keyrings/{self.archive_key}"
        self.sources_list_path = f"/etc/apt/sources.list.d/{self.sources_list}"

    def IsInstalled(self):
        return self.connection.DoesFileOrDirectoryExist("/usr/bin/wine")

    def Install(self):
        util.LogInfo("Installing Wine")
        self.connection.RunChecked([self.aptgetinstall_tool, "--add-architecture", "i386"], sudo = True)
        self.connection.DownloadFile(f"{self.url}/winehq.key", self.archive_key_path, sudo = True)
        self.connection.DownloadFile(f"{self.url}/ubuntu/dists/{self.codename}/{self.sources_list}", self.sources_list_path, sudo = True)
        self.connection.RunChecked([self.aptget_tool, "update"], sudo = True)
        self.connection.RunChecked([self.aptget_tool, "install", "-y", "winehq-devel"], sudo = True)
        self.connection.RunChecked([self.aptget_tool, "install", "-y", "winetricks"], sudo = True)
        return True

    def Uninstall(self):
        util.LogInfo("Uninstalling Wine")
        self.connection.RunChecked([self.aptget_tool, "remove", "-y", "winehq-devel"], sudo = True)
        self.connection.RunChecked([self.aptget_tool, "remove", "-y", "winetricks"], sudo = True)
        self.connection.RemoveFileOrDirectory(self.sources_list_path, sudo = True)
        self.connection.RemoveFileOrDirectory(self.archive_key_path, sudo = True)
        return True
