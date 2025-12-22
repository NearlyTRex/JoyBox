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

# WinUAE emulator
class WinUAE(emulatorbase.EmulatorBase):

    # Get name
    def GetName(self):
        return "WinUAE"

    # Get platforms
    def GetPlatforms(self):
        return []

    # Get config
    def GetConfig(self):
        return {
            "WinUAE": {
                "program": {
                    "windows": "WinUAE/windows/winuae64.exe",
                    "linux": "WinUAE/windows/winuae64.exe"
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
        if programs.ShouldProgramBeInstalled("WinUAE", "windows"):
            success = release.DownloadWebpageRelease(
                webpage_url = "https://www.winuae.net/download",
                webpage_base_url = "https://www.winuae.net",
                starts_with = "https://download.abime.net/winuae/releases/WinUAE",
                ends_with = "x64.zip",
                search_file = "winuae64.exe",
                install_name = "WinUAE",
                install_dir = programs.GetProgramInstallDir("WinUAE", "windows"),
                backups_dir = programs.GetProgramBackupDir("WinUAE", "windows"),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup WinUAE")
                return False
        return True

    # Setup offline
    def SetupOffline(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Setup windows program
        if programs.ShouldProgramBeInstalled("WinUAE", "windows"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetProgramBackupDir("WinUAE", "windows"),
                install_name = "WinUAE",
                install_dir = programs.GetProgramInstallDir("WinUAE", "windows"),
                search_file = "winuae64.exe",
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup WinUAE")
                return False
        return True
