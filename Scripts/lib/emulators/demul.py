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

# Demul emulator
class Demul(emulatorbase.EmulatorBase):

    # Get name
    def GetName(self):
        return "Demul"

    # Get platforms
    def GetPlatforms(self):
        return []

    # Get config
    def GetConfig(self):
        return {
            "Demul": {
                "program": {
                    "windows": "Demul/windows/demul.exe",
                    "linux": "Demul/windows/demul.exe"
                },
                "run_sandboxed": {
                    "windows": False,
                    "linux": True
                }
            }
        }

    # Setup
    def Setup(self, verbose = False, exit_on_failure = False):

        # Download windows program
        if programs.ShouldProgramBeInstalled("Demul", "windows"):
            success = release.DownloadWebpageRelease(
                webpage_url = "http://demul.emulation64.com/downloads/",
                webpage_base_url = "http://demul.emulation64.com",
                starts_with = "http://demul.emulation64.com/files/demul",
                ends_with = ".7z",
                search_file = "demul.exe",
                install_name = "Demul",
                install_dir = programs.GetProgramInstallDir("Demul", "windows"),
                backups_dir = programs.GetProgramBackupDir("Demul", "windows"),
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup Demul")

    # Setup offline
    def SetupOffline(self, verbose = False, exit_on_failure = False):

        # Setup windows program
        if programs.ShouldProgramBeInstalled("Demul", "windows"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetProgramBackupDir("Demul", "windows"),
                install_name = "Demul",
                install_dir = programs.GetProgramInstallDir("Demul", "windows"),
                search_file = "demul.exe",
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup Demul")
