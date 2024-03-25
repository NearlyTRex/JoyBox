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
    def Setup(self, verbose = False, exit_on_failure = False):

        # Download windows program
        if programs.ShouldProgramBeInstalled("Nestopia", "windows"):
            success = release.DownloadWebpageRelease(
                webpage_url = "http://0ldsk00l.ca/nestopia",
                webpage_base_url = "http://0ldsk00l.ca/nestopia",
                starts_with = "http://sourceforge.net/projects/nestopiaue/files/",
                ends_with = "win32.zip/download",
                search_file = "nestopia.exe",
                install_name = "Nestopia",
                install_dir = programs.GetProgramInstallDir("Nestopia", "windows"),
                backups_dir = programs.GetProgramBackupDir("Nestopia", "windows"),
                release_type = config.release_type_archive,
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup Nestopia")

    # Setup offline
    def SetupOffline(self, verbose = False, exit_on_failure = False):
        pass
