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

    def IsInstalled(self):
        return self.connection.DoesFileOrDirectoryExist("/usr/bin/wine")

    def Install(self):
        util.LogInfo("Installing Wine")
        self.connection.RunChecked("sudo dpkg --add-architecture i386")
        self.connection.RunChecked("sudo mkdir -pm755 /etc/apt/keyrings")
        self.connection.RunChecked(f"sudo wget -O /etc/apt/keyrings/{self.archive_key} {self.url}/winehq.key")
        self.connection.RunChecked(f"sudo wget -NP /etc/apt/sources.list.d/ {self.url}/ubuntu/dists/{self.codename}/{self.sources_list}")
        self.connection.RunChecked("sudo apt update")
        self.connection.RunChecked("sudo apt install -y winehq-devel winetricks")
        return True

    def Uninstall(self):
        util.LogInfo("Uninstalling Wine")
        self.connection.RunChecked("sudo apt remove -y winehq-devel winehq-stable wine-stable wine winetricks")
        self.connection.RunChecked(f"sudo rm -f /etc/apt/sources.list.d/{self.sources_list}")
        self.connection.RunChecked(f"sudo rm -f /etc/apt/keyrings/{self.archive_key}")
        self.connection.RunChecked("rm -rf ~/.wine ~/.local/share/applications/wine")
        return True
