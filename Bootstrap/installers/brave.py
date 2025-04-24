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
        connection,
        flags = util.RunFlags(),
        options = util.RunOptions()):
        super.__init__(connection, flags, options)

    def IsInstalled(self):
        return self.connection.DoesFileOrDirectoryExist("/usr/bin/brave-browser")

    def Install(self):

        # Check for already installed
        if self.IsInstalled():
            return True

        # Setup
        source_url = "https://brave-browser-apt-release.s3.brave.com"
        keyring_file = "brave-browser-archive-keyring.gpg"
        sources_file = "/etc/apt/sources.list.d/brave-browser-release.list"
        self.connection.RunChecked(f"sudo curl -fsSLo /usr/share/keyrings/{keyring_file} {source_url}/{keyring_file}")
        self.connection.RunChecked(f"echo 'deb [signed-by=/usr/share/keyrings/{keyring_file}] {source_url}/ stable main' | sudo tee {sources_file}")
        self.connection.RunChecked("sudo apt update")
        self.connection.RunChecked("sudo apt install -y brave-browser")
        return True
