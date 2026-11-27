# Local imports
from joybox.bootstrap import constants
from joybox import runoptions
from joybox import logger
from . import installer

# Installs Steam and SteamCMD from apt, with i386 enabled and the SteamCMD license pre-accepted
class Steam(installer.Installer):
    def __init__(
        self,
        connection,
        flags = runoptions.RunFlags(),
        options = runoptions.RunOptions()):
        super().__init__(connection, flags, options)

    # Local Ubuntu only
    def get_supported_environments(self):
        return [
            constants.EnvironmentType.LOCAL_UBUNTU,
        ]

    # Whether both /usr/games/steam and /usr/games/steamcmd exist
    def is_installed(self):
        steam_installed = self.connection.does_file_or_directory_exist("/usr/games/steam")
        steamcmd_installed = self.connection.does_file_or_directory_exist("/usr/games/steamcmd")
        return steam_installed and steamcmd_installed

    # steam and steamcmd as installed or missing, by their /usr/games binaries
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

    # Enable i386, apt-get install steam-installer (steam when that fails), preseed
    # the license, then install steamcmd; False when a step fails
    def install(self):

        # Start install
        logger.log_info("Installing Steam and SteamCMD")

        # Add i386 architecture and update package lists
        if not self._prepare_apt():
            return False

        # Install Steam
        if not self._install_steam_package():
            return False

        # Pre-accept Steam license for SteamCMD
        self._accept_steam_license()

        # Install SteamCMD
        logger.log_info("Installing SteamCMD")
        code = self.connection.run_blocking(
            [self.aptget_tool, "install", "-y", "steamcmd"],
            sudo=True
        )
        if code != 0:
            logger.log_error("Failed to install SteamCMD")
            return False

        # All done
        logger.log_info("Steam and SteamCMD installed successfully")
        return True

    # Enable the i386 architecture for 32-bit support, then apt-get update; False when either fails
    def _prepare_apt(self):

        # Add i386 architecture for 32-bit support
        logger.log_info("Adding i386 architecture")
        code = self.connection.run_blocking([self.aptgetinstall_tool, "--add-architecture", "i386"], sudo=True)
        if code != 0:
            logger.log_error("Failed to add i386 architecture")
            return False

        # Update package lists
        logger.log_info("Updating package lists")
        code = self.connection.run_blocking([self.aptget_tool, "update"], sudo=True)
        if code != 0:
            logger.log_error("Failed to update package lists")
            return False
        return True

    # apt-get install steam-installer, falling back to the steam package; False when both fail
    def _install_steam_package(self):
        logger.log_info("Installing Steam")
        code = self.connection.run_blocking(
            [self.aptget_tool, "install", "-y", "steam-installer"],
            sudo=True
        )
        if code != 0:
            logger.log_warning("steam-installer failed, trying steam package")
            code = self.connection.run_blocking(
                [self.aptget_tool, "install", "-y", "steam"],
                sudo=True
            )
            if code != 0:
                logger.log_error("Failed to install Steam")
                return False
        return True

    # Preseed debconf so SteamCMD installs without the license prompt
    def _accept_steam_license(self):
        logger.log_info("Accepting Steam license for SteamCMD")
        self.connection.run_blocking(
            ["sh", "-c", 'echo "steam steam/question select I AGREE" | debconf-set-selections'],
            sudo=True
        )
        self.connection.run_blocking(
            ["sh", "-c", 'echo "steam steam/license note \\"\\\"" | debconf-set-selections'],
            sudo=True
        )

    # apt-get remove steamcmd, steam-installer and steam
    def uninstall(self):

        # Start uninstall
        logger.log_info("Uninstalling Steam and SteamCMD")

        # Remove SteamCMD
        logger.log_info("Removing SteamCMD")
        self.connection.run_blocking(
            [self.aptget_tool, "remove", "-y", "steamcmd"],
            sudo=True
        )

        # Remove Steam
        logger.log_info("Removing Steam")
        self.connection.run_blocking(
            [self.aptget_tool, "remove", "-y", "steam-installer", "steam"],
            sudo=True
        )

        # All done
        logger.log_info("Steam and SteamCMD uninstalled")
        return True
