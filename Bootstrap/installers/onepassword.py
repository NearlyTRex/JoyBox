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
        connection,
        flags = util.RunFlags(),
        options = util.RunOptions()):
        super.__init__(connection, flags, options)

    def IsInstalled(self):
        return self.connection.DoesFileOrDirectoryExist("/usr/bin/1password")

    def Install(self):

        # Check for already installed
        if self.IsInstalled():
            return True

        # Setup
        self.connection.RunChecked("curl -sS https://downloads.1password.com/linux/keys/1password.asc | sudo gpg --dearmor --output /usr/share/keyrings/1password-archive-keyring.gpg")
        self.connection.RunChecked("echo 'deb [arch=amd64 signed-by=/usr/share/keyrings/1password-archive-keyring.gpg] https://downloads.1password.com/linux/debian/amd64 stable main' | sudo tee /etc/apt/sources.list.d/1password.list")
        self.connection.RunChecked("sudo mkdir -p /etc/debsig/policies/AC2D62742012EA22/")
        self.connection.RunChecked("curl -sS https://downloads.1password.com/linux/debian/debsig/1password.pol | sudo tee /etc/debsig/policies/AC2D62742012EA22/1password.pol")
        self.connection.RunChecked("sudo mkdir -p /usr/share/debsig/keyrings/AC2D62742012EA22")
        self.connection.RunChecked("curl -sS https://downloads.1password.com/linux/keys/1password.asc | sudo gpg --dearmor --output /usr/share/debsig/keyrings/AC2D62742012EA22/debsig.gpg")
        self.connection.RunChecked("sudo apt update")
        self.connection.RunChecked("sudo apt install -y 1password")
        return True
