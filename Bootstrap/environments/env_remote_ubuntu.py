# Imports
import os
import sys

# Local imports
import util
import constants
import connection
import installers
from . import env

# Remote Ubuntu
class RemoteUbuntu(env.Environment):
    def __init__(
        self,
        config,
        ssh_host = None,
        ssh_port = None,
        ssh_user = None,
        ssh_password = None,
        flags = util.RunFlags(),
        options = util.RunOptions()):
        super().__init__(config, flags, options)

        # Set environment type
        self.SetEnvironmentType(constants.EnvironmentType.REMOTE_UBUNTU)

        # Create connection
        self.connection = connection.ConnectionSSH(
            ssh_host = ssh_host,
            ssh_port = ssh_port,
            ssh_user = ssh_user,
            ssh_password = ssh_password,
            flags = self.flags,
            options = self.options)
        self.connection.Setup()

        # Create installer options
        self.installer_options = {
            "config": self.config,
            "connection": self.connection,
            "flags": self.flags,
            "options": self.options
        }

        # Create installers
        self.installer_aptget = installers.AptGet(**self.installer_options)
        self.installer_flatpak = installers.Flatpak(**self.installer_options)
        self.installer_wordress = installers.Wordpress(**self.installer_options)

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

        # Install Wordpress
        if not self.installer_wordress.IsInstalled():
            if not self.installer_wordress.Install():
                return False
        return True

    def Teardown(self):

        # Uninstall Wordpress
        if self.installer_wordress.IsInstalled():
            if not self.installer_wordress.Uninstall():
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
