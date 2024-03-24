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

# SameBoy emulator
class SameBoy(emulatorbase.EmulatorBase):

    # Get name
    def GetName(self):
        return "SameBoy"

    # Get platforms
    def GetPlatforms(self):
        return []

    # Get config
    def GetConfig(self):
        return {
            "SameBoy": {
                "program": {
                    "windows": "SameBoy/windows/sameboy.exe",
                    "linux": "SameBoy/windows/sameboy.exe"
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
        if programs.ShouldProgramBeInstalled("SameBoy", "windows"):
            success = release.DownloadGithubRelease(
                github_user = "LIJI32",
                github_repo = "SameBoy",
                starts_with = "sameboy_winsdl",
                ends_with = ".zip",
                search_file = "sameboy.exe",
                install_name = "SameBoy",
                install_dir = programs.GetProgramInstallDir("SameBoy", "windows"),
                backups_dir = programs.GetProgramBackupDir("SameBoy", "windows"),
                release_type = config.release_type_archive,
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup SameBoy")
