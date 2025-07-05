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

        # Create connection
        self.connection = connection.ConnectionLocal(self.config, self.flags, self.options)
        self.connection.Setup()

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
            "onepassword": installers.OnePassword(**self.installer_options),
            "wine": installers.Wine(**self.installer_options)
        }

        # Get individual installers
        self.installer_aptget = self.available_components["aptget"]
        self.installer_flatpak = self.available_components["flatpak"]
        self.installer_chrome = self.available_components["chrome"]
        self.installer_brave = self.available_components["brave"]
        self.installer_onepassword = self.available_components["onepassword"]
        self.installer_wine = self.available_components["wine"]

    def Setup(self):

        # Update package lists
        if self.ShouldProcessComponent("aptget"):
            util.LogInfo("Updating package lists for AptGet")
            self.installer_aptget.UpdatePackageLists()

        # Process all components
        success = self.ProcessComponents("Install")

        # Autoremove packages
        if self.ShouldProcessComponent("aptget") and success:
            if not self.installer_aptget.AutoRemovePackages():
                return False
        return success

    def Teardown(self):

        # Process components in reverse order
        success = self.ProcessComponents("Uninstall", reverse_order = True)

        # Autoremove packages
        if self.ShouldProcessComponent("aptget") and success:
            if not self.installer_aptget.AutoRemovePackages():
                return False
        return success
