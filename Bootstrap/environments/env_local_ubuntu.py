# Imports
import os
import sys

# Local imports
import util
import constants
import connection
import installers
from . import env

# Local Ubuntu
class LocalUbuntu(env.Environment):
    def __init__(
        self,
        config,
        flags = util.RunFlags(),
        options = util.RunOptions()):
        super().__init__(config, flags, options)

        # Set environment type
        self.SetEnvironmentType(constants.EnvironmentType.LOCAL_UBUNTU)

        # Create installer options
        self.installer_options = {
            "config": self.config,
            "connection": connection.ConnectionLocal(self.flags, self.options),
            "flags": self.flags,
            "options": self.options}

        # Create installers
        self.installer_aptget = installers.AptGet(**self.installer_options)
        self.installer_flatpak = installers.Flatpak(**self.installer_options)
        self.installer_chrome = installers.Chrome(**self.installer_options)
        self.installer_brave = installers.Brave(**self.installer_options)
        self.installer_onepassword = installers.OnePassword(**self.installer_options)
        self.installer_wine = installers.Wine(**self.installer_options)

    def Setup(self):

        # Install AptGet packages
        self.installer_aptget.UpdatePackageLists()
        if not self.installer_aptget.IsInstalled():
            self.installer_aptget.Install()
        self.installer_aptget.AutoRemovePackages()

        # Install Flatpak packages
        self.installer_flatpak.UpdatePackages()
        if not self.installer_flatpak.IsInstalled():
            self.installer_flatpak.Install()

        # Install Chrome
        if not self.installer_chrome.IsInstalled():
            self.installer_chrome.Install()

        # Install Brave
        if not self.installer_brave.IsInstalled():
            self.installer_brave.Install()

        # Install 1Password
        if not self.installer_onepassword.IsInstalled():
            self.installer_onepassword.Install()

        # Install Wine
        if not self.installer_wine.IsInstalled():
            self.installer_wine.Install()
        return True

    def Teardown(self):
        return True
