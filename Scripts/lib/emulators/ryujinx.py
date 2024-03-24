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

# Ryujinx emulator
class Ryujinx(emulatorbase.EmulatorBase):

    # Get name
    def GetName(self):
        return "Ryujinx"

    # Get platforms
    def GetPlatforms(self):
        return []

    # Get config
    def GetConfig(self):
        return {
            "Ryujinx": {
                "program": {
                    "windows": "Ryujinx/windows/Ryujinx.exe",
                    "linux": "Ryujinx/windows/Ryujinx.exe"
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
        if programs.ShouldProgramBeInstalled("Ryujinx", "windows"):
            success = release.DownloadGithubRelease(
                github_user = "Ryujinx",
                github_repo = "release-channel-master",
                starts_with = "ryujinx",
                ends_with = "win_x64.zip",
                search_file = "Ryujinx.exe",
                install_name = "Ryujinx",
                install_dir = programs.GetProgramInstallDir("Ryujinx", "windows"),
                backups_dir = programs.GetProgramBackupDir("Ryujinx", "windows"),
                release_type = config.release_type_archive,
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup Ryujinx")
