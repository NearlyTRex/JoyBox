# Imports
import os, os.path
import sys

# Local imports
import config
import environment
import system
import release
import programs
import emulatorbase

# Config files
config_files = {}

# System files
system_files = {}

# BlastEm emulator
class BlastEm(emulatorbase.EmulatorBase):

    # Get name
    def GetName(self):
        return "BlastEm"

    # Get platforms
    def GetPlatforms(self):
        return []

    # Get config
    def GetConfig(self):
        return {
            "BlastEm": {
                "program": {
                    "windows": "BlastEm/windows/blastem.exe",
                    "linux": "BlastEm/windows/blastem.exe"
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
        if programs.ShouldProgramBeInstalled("BlastEm", "windows"):
            success = release.DownloadWebpageRelease(
                webpage_url = "https://www.retrodev.com/blastem",
                webpage_base_url = "https://www.retrodev.com/blastem",
                starts_with = "https://www.retrodev.com/blastem/blastem-win32",
                ends_with = ".zip",
                search_file = "blastem.exe",
                install_name = "BlastEm",
                install_dir = programs.GetProgramInstallDir("BlastEm", "windows"),
                backups_dir = programs.GetProgramBackupDir("BlastEm", "windows"),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                system.LogError("Could not setup BlastEm")
                return False
        return True

    # Setup offline
    def SetupOffline(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Setup windows program
        if programs.ShouldProgramBeInstalled("BlastEm", "windows"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetProgramBackupDir("BlastEm", "windows"),
                install_name = "BlastEm",
                install_dir = programs.GetProgramInstallDir("BlastEm", "windows"),
                search_file = "blastem.exe",
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                system.LogError("Could not setup BlastEm")
                return False
        return True
