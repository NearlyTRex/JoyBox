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
        self.set_environment_type(constants.EnvironmentType.LOCAL_UBUNTU)

        # Create connection
        self.connection = connection.ConnectionLocal(self.config, self.flags, self.options)
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
            "aptget": installers.AptGet(**self.installer_options),
            "flatpak": installers.Flatpak(**self.installer_options),
            "chrome": installers.Chrome(**self.installer_options),
            "brave": installers.Brave(**self.installer_options),
            "gitkraken": installers.GitKraken(**self.installer_options),
            "onepassword": installers.OnePassword(**self.installer_options),
            "vscodium": installers.VSCodium(**self.installer_options),
            "wine": installers.Wine(**self.installer_options)
        }

        # Get individual installers
        self.installer_aptget = self.available_components["aptget"]
        self.installer_flatpak = self.available_components["flatpak"]
        self.installer_chrome = self.available_components["chrome"]
        self.installer_brave = self.available_components["brave"]
        self.installer_gitkraken = self.available_components["gitkraken"]
        self.installer_onepassword = self.available_components["onepassword"]
        self.installer_vscodium = self.available_components["vscodium"]
        self.installer_wine = self.available_components["wine"]

    def setup(self):

        # Update package lists
        if self.should_process_component("aptget"):
            util.log_info("Updating package lists for AptGet")
            self.installer_aptget.UpdatePackageLists()

        # Process all components
        success = self.process_components("install")

        # Autoremove packages
        if self.should_process_component("aptget") and success:
            if not self.installer_aptget.AutoRemovePackages():
                return False
        return success

    def teardown(self):

        # Process components in reverse order
        success = self.process_components("uninstall", reverse_order = True)

        # Autoremove packages
        if self.should_process_component("aptget") and success:
            if not self.installer_aptget.AutoRemovePackages():
                return False
        return success
