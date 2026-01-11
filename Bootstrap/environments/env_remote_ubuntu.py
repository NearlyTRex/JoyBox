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
        self.set_environment_type(constants.EnvironmentType.REMOTE_UBUNTU)

        # Create connection
        self.connection = connection.ConnectionSSH(
            config = self.config,
            ssh_host = ssh_host,
            ssh_port = ssh_port,
            ssh_user = ssh_user,
            ssh_password = ssh_password,
            flags = self.flags,
            options = self.options)
        self.connection.setup()

        # Create installer options
        self.installer_options = {
            "config": self.config,
            "connection": self.connection,
            "flags": self.flags,
            "options": self.options
        }

        # Create components
        self.available_components = {
            "config": installers.Config(**self.installer_options),
            "dotfiles": installers.Dotfiles(**self.installer_options),
            "python": installers.Python(**self.installer_options),
            "wrappers": installers.Wrappers(**self.installer_options),
            "aptget": installers.AptGet(**self.installer_options),
            "awscli": installers.AwsCli(**self.installer_options),
            "flatpak": installers.Flatpak(**self.installer_options),
            "nginx": installers.Nginx(**self.installer_options),
            "certbot": installers.Certbot(**self.installer_options),
            "claude": installers.Claude(**self.installer_options),
            "cockpit": installers.Cockpit(**self.installer_options),
            "wordpress": installers.Wordpress(**self.installer_options),
            "audiobookshelf": installers.Audiobookshelf(**self.installer_options),
            "navidrome": installers.Navidrome(**self.installer_options),
            "filebrowser": installers.FileBrowser(**self.installer_options),
            "jenkins": installers.Jenkins(**self.installer_options),
            "kanboard": installers.Kanboard(**self.installer_options),
            "ghidra": installers.Ghidra(**self.installer_options)
        }

        # Get individual installers
        self.installer_config = self.available_components["config"]
        self.installer_dotfiles = self.available_components["dotfiles"]
        self.installer_python = self.available_components["python"]
        self.installer_wrappers = self.available_components["wrappers"]
        self.installer_aptget = self.available_components["aptget"]
        self.installer_awscli = self.available_components["awscli"]
        self.installer_audiobookshelf = self.available_components["audiobookshelf"]
        self.installer_flatpak = self.available_components["flatpak"]
        self.installer_nginx = self.available_components["nginx"]
        self.installer_certbot = self.available_components["certbot"]
        self.installer_claude = self.available_components["claude"]
        self.installer_cockpit = self.available_components["cockpit"]
        self.installer_wordpress = self.available_components["wordpress"]
        self.installer_filebrowser = self.available_components["filebrowser"]
        self.installer_jenkins = self.available_components["jenkins"]
        self.installer_navidrome = self.available_components["navidrome"]
        self.installer_kanboard = self.available_components["kanboard"]
        self.installer_ghidra = self.available_components["ghidra"]

    def setup(self):

        # Update package lists and autoremove
        if self.should_process_component("aptget"):
            util.log_info("Updating package lists for AptGet")
            self.installer_aptget.update_package_lists()
            util.log_info("Auto-removing unused packages")
            self.installer_aptget.auto_remove_packages()

        # Process all components
        success = self.process_components("install", force=self.flags.force)

        # Autoremove packages
        if self.should_process_component("aptget") and success:
            if not self.installer_aptget.auto_remove_packages():
                return False
        return success

    def teardown(self):

        # Process components in reverse order
        success = self.process_components("uninstall", reverse_order=True, force=self.flags.force)

        # Autoremove packages
        if self.should_process_component("aptget") and success:
            if not self.installer_aptget.auto_remove_packages():
                return False
        return success
