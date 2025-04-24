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
        connection,
        flags = util.RunFlags(),
        options = util.RunOptions()):
        super.__init__(connection, flags, options)

    def IsInstalled(self):
        return self.connection.DoesFileOrDirectoryExist("/usr/bin/wine")

    def Install(self):

        # Check for already installed
        if self.IsInstalled():
            return True

        # Setup
        ubuntu_codename = util.GetUbuntuCodename()
        self.connection.RunChecked("sudo dpkg --add-architecture i386")
        self.connection.RunChecked("sudo mkdir -pm755 /etc/apt/keyrings")
        self.connection.RunChecked("sudo wget -O /etc/apt/keyrings/winehq-archive.key https://dl.winehq.org/wine-builds/winehq.key")
        self.connection.RunChecked("sudo wget -NP /etc/apt/sources.list.d/ https://dl.winehq.org/wine-builds/ubuntu/dists/%s/winehq-%s.sources" % (ubuntu_codename, ubuntu_codename))
        self.connection.RunChecked("sudo apt update")
        self.connection.RunChecked("sudo apt install -y winehq-devel winetricks")
        return True
