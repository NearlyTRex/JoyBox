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

# Phoenix emulator
class Phoenix(emulatorbase.EmulatorBase):

    # Get name
    def GetName(self):
        return "Phoenix"

    # Get platforms
    def GetPlatforms(self):
        return []

    # Get config
    def GetConfig(self):
        return {
            "Phoenix": {
                "program": {
                    "windows": "Phoenix/windows/PhoenixEmuProject.exe",
                    "linux": "Phoenix/windows/PhoenixEmuProject.exe"
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
        if programs.ShouldProgramBeInstalled("Phoenix", "windows"):
            success = release.DownloadGeneralRelease(
                archive_url = "https://archive.org/download/PHX_EMU/ph28jag-win64.zip",
                search_file = "PhoenixEmuProject.exe",
                install_name = "Phoenix",
                install_dir = programs.GetProgramInstallDir("Phoenix", "windows"),
                backups_dir = programs.GetProgramBackupDir("Phoenix", "windows"),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup Phoenix")
                return False
        return True

    # Setup offline
    def SetupOffline(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Setup windows program
        if programs.ShouldProgramBeInstalled("Phoenix", "windows"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetProgramBackupDir("Phoenix", "windows"),
                install_name = "Phoenix",
                install_dir = programs.GetProgramInstallDir("Phoenix", "windows"),
                search_file = "PhoenixEmuProject.exe",
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup Phoenix")
                return False
        return True
