# Imports
import os
import sys

# Local imports
import util
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

    def IsInstalled(self):
        return self.connection.DoesFileOrDirectoryExist("/usr/bin/brave-browser")

    def Install(self):
        util.LogInfo("Installing Brave")
        self.connection.RunChecked(f"sudo curl -fsSLo /usr/share/keyrings/{self.archive_key} {self.url}/{self.archive_key}")
        self.connection.RunChecked(f"echo 'deb [signed-by=/usr/share/keyrings/{self.archive_key}] {self.url}/ stable main' | sudo tee /etc/apt/sources.list.d/{self.sources_list}")
        self.connection.RunChecked("sudo apt update")
        self.connection.RunChecked("sudo apt install -y brave-browser")
        return True

    def Uninstall(self):
        util.LogInfo("Uninstalling Brave")
        self.connection.RunChecked("sudo apt remove -y brave-browser")
        self.connection.RunChecked(f"sudo rm -f /etc/apt/sources.list.d/{self.sources_list}")
        self.connection.RunChecked(f"sudo rm -f /usr/share/keyrings/{self.archive_key}")
        return False
