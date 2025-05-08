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
        self.installer_flatpak = installers.Flatpak(**self.installer_options)
        self.installer_nginx = installers.Nginx(**self.installer_options)
        self.installer_certbot = installers.Certbot(**self.installer_options)
        self.installer_wordpress = installers.Wordpress(**self.installer_options)
        self.installer_azuracast = installers.AzuraCast(**self.installer_options)
        self.installer_nextcloud = installers.NextCloud(**self.installer_options)
        self.installer_scriptserver = installers.ScriptServer(**self.installer_options)

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

        # Install Wordpress
        util.LogInfo("Installing Wordpress")
        if not self.installer_wordpress.IsInstalled():
            if not self.installer_wordpress.Install():
                return False

        # Install AzuraCast
        util.LogInfo("Installing AzuraCast")
        if not self.installer_azuracast.IsInstalled():
            if not self.installer_azuracast.Install():
                return False

        # Install NextCloud
        util.LogInfo("Installing NextCloud")
        if not self.installer_nextcloud.IsInstalled():
            if not self.installer_nextcloud.Install():
                return False

        # Install ScriptServer
        util.LogInfo("Installing ScriptServer")
        if not self.installer_scriptserver.IsInstalled():
            if not self.installer_scriptserver.Install():
                return False
        return True

    def Teardown(self):

        # Uninstall ScriptServer
        util.LogInfo("Uninstalling ScriptServer")
        if self.installer_scriptserver.IsInstalled():
            if not self.installer_scriptserver.Uninstall():
                return False

        # Uninstall NextCloud
        util.LogInfo("Uninstalling NextCloud")
        if self.installer_nextcloud.IsInstalled():
            if not self.installer_nextcloud.Uninstall():
                return False

        # Uninstall AzuraCast
        util.LogInfo("Uninstalling AzuraCast")
        if self.installer_azuracast.IsInstalled():
            if not self.installer_azuracast.Uninstall():
                return False

        # Uninstall Wordpress
        util.LogInfo("Uninstalling Wordpress")
        if self.installer_wordpress.IsInstalled():
            if not self.installer_wordpress.Uninstall():
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
