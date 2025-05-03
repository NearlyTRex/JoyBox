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
        super.__init__(config, connection, flags, options)
        self.policy = "AC2D62742012EA22"
        self.url = f"https://downloads.1password.com"
        self.archive_key = "1password-archive-keyring.gpg"
        self.sources_list = "1password.list"

    def IsInstalled(self):
        return self.connection.DoesFileOrDirectoryExist("/usr/bin/1password")

    def Install(self):
        util.LogInfo("Installing 1Password")
        self.connection.RunChecked(f"curl -sS {self.url}/linux/keys/1password.asc | sudo gpg --dearmor --output /usr/share/keyrings/{self.archive_key}")
        self.connection.RunChecked(f"echo 'deb [arch=amd64 signed-by=/usr/share/keyrings/{self.archive_key}] {self.url}/linux/debian/amd64 stable main' | sudo tee /etc/apt/sources.list.d/{self.sources_list}")
        self.connection.RunChecked(f"sudo mkdir -p /etc/debsig/policies/{self.policy}/")
        self.connection.RunChecked(f"curl -sS {self.url}/linux/debian/debsig/1password.pol | sudo tee /etc/debsig/policies/{self.policy}/1password.pol")
        self.connection.RunChecked(f"sudo mkdir -p /usr/share/debsig/keyrings/{self.policy}")
        self.connection.RunChecked(f"curl -sS {self.url}/linux/keys/1password.asc | sudo gpg --dearmor --output /usr/share/debsig/keyrings/{self.policy}/debsig.gpg")
        self.connection.RunChecked("sudo apt update")
        self.connection.RunChecked("sudo apt install -y 1password")
        return True

    def Uninstall(self):
        util.LogInfo("Uninstalling 1Password")
        self.connection.RunChecked("sudo apt remove -y 1password")
        self.connection.RunChecked(f"sudo rm -f /etc/apt/sources.list.d/{self.sources_list}")
        self.connection.RunChecked(f"sudo rm -f /usr/share/keyrings/{self.archive_key}")
        self.connection.RunChecked(f"sudo rm -rf /etc/debsig/policies/{self.policy}/")
        self.connection.RunChecked(f"sudo rm -rf /usr/share/debsig/keyrings/{self.policy}")
        return True
