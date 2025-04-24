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
        connection,
        flags = util.RunFlags(),
        options = util.RunOptions()):
        super.__init__(connection, flags, options)

    def IsInstalled(self):
        return self.connection.DoesFileOrDirectoryExist("/usr/bin/google-chrome")

    def Install(self):

        # Check for already installed
        if self.IsInstalled():
            return True

        # Setup
        self.connection.RunChecked("wget -c -O /tmp/google-chrome.deb https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb")
        self.connection.RunChecked("sudo dpkg -i google-chrome-stable_current_amd64.deb")
        self.connection.RunChecked("rm -rf /tmp/google-chrome.deb")
        return True
