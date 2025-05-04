# Imports
import os
import sys

# Local imports
import util
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

    def IsInstalled(self):
        return self.connection.DoesFileOrDirectoryExist("/usr/bin/google-chrome")

    def Install(self):
        util.LogInfo("Installing Chrome")
        self.connection.RunChecked(f"wget -c -O /tmp/google-chrome.deb {self.url}/google-chrome-stable_current_amd64.deb")
        self.connection.RunChecked("sudo dpkg -i /tmp/google-chrome.deb")
        self.connection.RunChecked("rm -rf /tmp/google-chrome.deb")
        return True

    def Uninstall(self):
        util.LogInfo("Uninstalling Chrome")
        self.connection.RunChecked("sudo apt remove -y google-chrome-stable")
        self.connection.RunChecked(f"sudo rm -f /etc/apt/sources.list.d/{self.sources_list}")
        self.connection.RunChecked(f"sudo rm -f /etc/apt/trusted.gpg.d/{self.archive_key}")
        return False
