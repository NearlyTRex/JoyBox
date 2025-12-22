# Imports
import os, os.path
import sys

# Local imports
import config
import environment
import system
import logger
import release
import programs
import emulatorbase

# Config files
config_files = {}

# System files
system_files = {}

# Nestopia emulator
class Nestopia(emulatorbase.EmulatorBase):

    # Get name
    def GetName(self):
        return "Nestopia"

    # Get platforms
    def GetPlatforms(self):
        return []

    # Get config
    def GetConfig(self):
        return {
            "Nestopia": {
                "program": {
                    "windows": "Nestopia/windows/nestopia.exe",
                    "linux": "Nestopia/windows/nestopia.exe"
                },
                "run_sandboxed": {
                    "windows": False,
                    "linux": True
                }
            }
        }

    # Setup
    def Setup(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Download windows program
        if programs.ShouldProgramBeInstalled("Nestopia", "windows"):
            success = release.DownloadGithubRelease(
                github_user = "0ldsk00l",
                github_repo = "nestopia",
                starts_with = "nestopia",
                ends_with = "win32.zip",
                search_file = "nestopia.exe",
                install_name = "Nestopia",
                install_dir = programs.GetProgramInstallDir("Nestopia", "windows"),
                backups_dir = programs.GetProgramBackupDir("Nestopia", "windows"),
                get_latest = True,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup Nestopia")
                return False
        return True

    # Setup offline
    def SetupOffline(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Setup windows program
        if programs.ShouldProgramBeInstalled("Nestopia", "windows"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetProgramBackupDir("Nestopia", "windows"),
                install_name = "Nestopia",
                install_dir = programs.GetProgramInstallDir("Nestopia", "windows"),
                search_file = "nestopia.exe",
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup Nestopia")
                return False
        return True
