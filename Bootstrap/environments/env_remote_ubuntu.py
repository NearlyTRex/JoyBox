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
            config = self.config,
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
        self.installer_audiobookshelf = installers.Audiobookshelf(**self.installer_options)
        self.installer_flatpak = installers.Flatpak(**self.installer_options)
        self.installer_nginx = installers.Nginx(**self.installer_options)
        self.installer_certbot = installers.Certbot(**self.installer_options)
        self.installer_cockpit = installers.Cockpit(**self.installer_options)
        self.installer_wordpress = installers.Wordpress(**self.installer_options)
        self.installer_filebrowser = installers.FileBrowser(**self.installer_options)
        self.installer_jenkins = installers.Jenkins(**self.installer_options)
        self.installer_navidrome = installers.Navidrome(**self.installer_options)
        self.installer_kanboard = installers.Kanboard(**self.installer_options)
        self.installer_ghidra = installers.Ghidra(**self.installer_options)

    def Setup(self):

        # Install AptGet packages
        util.LogInfo("Installing AptGet packages")
        self.installer_aptget.UpdatePackageLists()
        if not self.installer_aptget.IsInstalled():
            if not self.installer_aptget.Install():
                return False
        if not self.installer_aptget.AutoRemovePackages():
            return False

        # Install Flatpak packages
        util.LogInfo("Installing Flatpak packages")
        self.installer_flatpak.UpdatePackages()
        if not self.installer_flatpak.IsInstalled():
            if not self.installer_flatpak.Install():
                return False

        # Install Nginx
        util.LogInfo("Installing Nginx")
        if not self.installer_nginx.IsInstalled():
            if not self.installer_nginx.Install():
                return False

        # Install Certbot
        util.LogInfo("Installing Certbot")
        if not self.installer_certbot.IsInstalled():
            if not self.installer_certbot.Install():
                return False

        # Install Cockpit
        util.LogInfo("Installing Cockpit")
        if not self.installer_cockpit.IsInstalled():
            if not self.installer_cockpit.Install():
                return False

        # Install Wordpress
        util.LogInfo("Installing Wordpress")
        if not self.installer_wordpress.IsInstalled():
            if not self.installer_wordpress.Install():
                return False

        # Install Audiobookshelf
        util.LogInfo("Installing Audiobookshelf")
        if not self.installer_audiobookshelf.IsInstalled():
            if not self.installer_audiobookshelf.Install():
                return False

        # Install Navidrome
        util.LogInfo("Installing Navidrome")
        if not self.installer_navidrome.IsInstalled():
            if not self.installer_navidrome.Install():
                return False

        # Install FileBrowser
        util.LogInfo("Installing FileBrowser")
        if not self.installer_filebrowser.IsInstalled():
            if not self.installer_filebrowser.Install():
                return False

        # Install Jenkins
        util.LogInfo("Installing Jenkins")
        if not self.installer_jenkins.IsInstalled():
            if not self.installer_jenkins.Install():
                return False

        # Install Kanboard
        util.LogInfo("Installing Kanboard")
        if not self.installer_kanboard.IsInstalled():
            if not self.installer_kanboard.Install():
                return False

        # Install Ghidra
        util.LogInfo("Installing Ghidra")
        if not self.installer_ghidra.IsInstalled():
            if not self.installer_ghidra.Install():
                return False
        return True

    def Teardown(self):

        # Uninstall Ghidra
        util.LogInfo("Uninstalling Ghidra")
        if self.installer_ghidra.IsInstalled():
            if not self.installer_ghidra.Uninstall():
                return False

        # Uninstall Kanboard
        util.LogInfo("Uninstalling Kanboard")
        if self.installer_kanboard.IsInstalled():
            if not self.installer_kanboard.Uninstall():
                return False

        # Uninstall Jenkins
        util.LogInfo("Uninstalling Jenkins")
        if self.installer_jenkins.IsInstalled():
            if not self.installer_jenkins.Uninstall():
                return False

        # Uninstall FileBrowser
        util.LogInfo("Uninstalling FileBrowser")
        if self.installer_filebrowser.IsInstalled():
            if not self.installer_filebrowser.Uninstall():
                return False

        # Uninstall Navidrome
        util.LogInfo("Uninstalling Navidrome")
        if self.installer_navidrome.IsInstalled():
            if not self.installer_navidrome.Uninstall():
                return False

        # Uninstall Audiobookshelf
        util.LogInfo("Uninstalling Audiobookshelf")
        if self.installer_audiobookshelf.IsInstalled():
            if not self.installer_audiobookshelf.Uninstall():
                return False

        # Uninstall Wordpress
        util.LogInfo("Uninstalling Wordpress")
        if self.installer_wordpress.IsInstalled():
            if not self.installer_wordpress.Uninstall():
                return False

        # Uninstall Cockpit
        util.LogInfo("Uninstalling Cockpit")
        if self.installer_cockpit.IsInstalled():
            if not self.installer_cockpit.Uninstall():
                return False

        # Uninstall Certbot
        util.LogInfo("Uninstalling Certbot")
        if self.installer_certbot.IsInstalled():
            if not self.installer_certbot.Uninstall():
                return False

        # Uninstall Nginx
        util.LogInfo("Uninstalling Nginx")
        if self.installer_nginx.IsInstalled():
            if not self.installer_nginx.Uninstall():
                return False

        # Uninstall Flatpak packages
        util.LogInfo("Uninstalling Flatpak packages")
        if self.installer_flatpak.IsInstalled():
            if not self.installer_flatpak.Uninstall():
                return False

        # Uninstall AptGet packages
        util.LogInfo("Uninstalling AptGet packages")
        if self.installer_aptget.IsInstalled():
            if not self.installer_aptget.Uninstall():
                return False
        if not self.installer_aptget.AutoRemovePackages():
            return False
        return True
