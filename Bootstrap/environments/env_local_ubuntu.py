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
            if not self.installer_aptget.Install():
                return False
        if not self.installer_aptget.AutoRemovePackages():
            return False

        # Install Flatpak packages
        self.installer_flatpak.UpdatePackages()
        if not self.installer_flatpak.IsInstalled():
            if not self.installer_flatpak.Install():
                return False

        # Install Chrome
        if not self.installer_chrome.IsInstalled():
            if not self.installer_chrome.Install():
                return False

        # Install Brave
        if not self.installer_brave.IsInstalled():
            if not self.installer_brave.Install():
                return False

        # Install 1Password
        if not self.installer_onepassword.IsInstalled():
            if not self.installer_onepassword.Install():
                return False

        # Install Wine
        if not self.installer_wine.IsInstalled():
            if not self.installer_wine.Install():
                return False
        return True

    def Teardown(self):

        # Uninstall Wine
        if self.installer_wine.IsInstalled():
            if not self.installer_wine.Uninstall():
                return False

        # Uninstall 1Password
        if self.installer_onepassword.IsInstalled():
            if not self.installer_onepassword.Uninstall():
                return False

        # Uninstall Brave
        if self.installer_brave.IsInstalled():
            if not self.installer_brave.Uninstall():
                return False

        # Uninstall Chrome
        if self.installer_chrome.IsInstalled():
            if not self.installer_chrome.Uninstall():
                return False

        # Uninstall Flatpak packages
        if self.installer_flatpak.IsInstalled():
            if not self.installer_flatpak.Uninstall():
                return False

        # Uninstall AptGet packages
        if self.installer_aptget.IsInstalled():
            if not self.installer_aptget.Uninstall():
                return False
        if not self.installer_aptget.AutoRemovePackages():
            return False
        return True
