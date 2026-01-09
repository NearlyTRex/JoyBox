# Imports
import os
import sys

# Local imports
import util
import constants
from . import installer

# Steam
class Steam(installer.Installer):
    def __init__(
        self,
        config,
        connection,
        flags = util.RunFlags(),
        options = util.RunOptions()):
        super().__init__(config, connection, flags, options)

    def get_supported_environments(self):
        return [
            constants.EnvironmentType.LOCAL_UBUNTU,
        ]

    def is_installed(self):
        steam_installed = self.connection.does_file_or_directory_exist("/usr/games/steam")
        steamcmd_installed = self.connection.does_file_or_directory_exist("/usr/games/steamcmd")
        return steam_installed and steamcmd_installed

    def get_package_status(self):
        installed = []
        missing = []
        if self.connection.does_file_or_directory_exist("/usr/games/steam"):
            installed.append("steam")
        else:
            missing.append("steam")
        if self.connection.does_file_or_directory_exist("/usr/games/steamcmd"):
            installed.append("steamcmd")
        else:
            missing.append("steamcmd")
        return {"installed": installed, "missing": missing}

    def install(self):

        # Start install
        util.log_info("Installing Steam and SteamCMD")

        # Add i386 architecture for 32-bit support
        util.log_info("Adding i386 architecture")
        code = self.connection.run_blocking(["dpkg", "--add-architecture", "i386"], sudo=True)
        if code != 0:
            util.log_error("Failed to add i386 architecture")
            return False

        # Update package lists
        util.log_info("Updating package lists")
        code = self.connection.run_blocking([self.aptget_tool, "update"], sudo=True)
        if code != 0:
            util.log_error("Failed to update package lists")
            return False

        # Install Steam
        util.log_info("Installing Steam")
        code = self.connection.run_blocking(
            [self.aptget_tool, "install", "-y", "steam-installer"],
            sudo=True
        )
        if code != 0:
            util.log_warning("steam-installer failed, trying steam package")
            code = self.connection.run_blocking(
                [self.aptget_tool, "install", "-y", "steam"],
                sudo=True
            )
            if code != 0:
                util.log_error("Failed to install Steam")
                return False

        # Pre-accept Steam license for SteamCMD
        util.log_info("Accepting Steam license for SteamCMD")
        self.connection.run_blocking(
            ["sh", "-c", 'echo "steam steam/question select I AGREE" | debconf-set-selections'],
            sudo=True
        )
        self.connection.run_blocking(
            ["sh", "-c", 'echo "steam steam/license note \\"\\\"" | debconf-set-selections'],
            sudo=True
        )

        # Install SteamCMD
        util.log_info("Installing SteamCMD")
        code = self.connection.run_blocking(
            [self.aptget_tool, "install", "-y", "steamcmd"],
            sudo=True
        )
        if code != 0:
            util.log_error("Failed to install SteamCMD")
            return False

        # All done
        util.log_info("Steam and SteamCMD installed successfully")
        return True

    def uninstall(self):

        # Start uninstall
        util.log_info("Uninstalling Steam and SteamCMD")

        # Remove SteamCMD
        util.log_info("Removing SteamCMD")
        self.connection.run_blocking(
            [self.aptget_tool, "remove", "-y", "steamcmd"],
            sudo=True
        )

        # Remove Steam
        util.log_info("Removing Steam")
        self.connection.run_blocking(
            [self.aptget_tool, "remove", "-y", "steam-installer", "steam"],
            sudo=True
        )

        # All done
        util.log_info("Steam and SteamCMD uninstalled")
        return True
