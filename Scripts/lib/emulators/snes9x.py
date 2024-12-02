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

# Snes9x emulator
class Snes9x(emulatorbase.EmulatorBase):

    # Get name
    def GetName(self):
        return "Snes9x"

    # Get platforms
    def GetPlatforms(self):
        return []

    # Get config
    def GetConfig(self):
        return {
            "Snes9x": {
                "program": {
                    "windows": "Snes9x/windows/snes9x-x64.exe",
                    "linux": "Snes9x/linux/Snes9x.AppImage"
                },
                "run_sandboxed": {
                    "windows": False,
                    "linux": False
                }
            }
        }

    # Setup
    def Setup(self, verbose = False, pretend_run = False, exit_on_failure = False):

        # Download windows program
        if programs.ShouldProgramBeInstalled("Snes9x", "windows"):
            success = release.DownloadGithubRelease(
                github_user = "snes9xgit",
                github_repo = "snes9x",
                starts_with = "snes9x",
                ends_with = "win32-x64.zip",
                search_file = "snes9x-x64.exe",
                install_name = "Snes9x",
                install_dir = programs.GetProgramInstallDir("Snes9x", "windows"),
                backups_dir = programs.GetProgramBackupDir("Snes9x", "windows"),
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup Snes9x")

        # Download linux program
        if programs.ShouldProgramBeInstalled("Snes9x", "linux"):
            success = release.DownloadGithubRelease(
                github_user = "snes9xgit",
                github_repo = "snes9x",
                starts_with = "Snes9x",
                ends_with = "x86_64.AppImage",
                install_name = "Snes9x",
                install_dir = programs.GetProgramInstallDir("Snes9x", "linux"),
                backups_dir = programs.GetProgramBackupDir("Snes9x", "linux"),
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup Snes9x")

    # Setup offline
    def SetupOffline(self, verbose = False, pretend_run = False, exit_on_failure = False):

        # Setup windows program
        if programs.ShouldProgramBeInstalled("Snes9x", "windows"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetProgramBackupDir("Snes9x", "windows"),
                install_name = "Snes9x",
                install_dir = programs.GetProgramInstallDir("Snes9x", "windows"),
                search_file = "snes9x-x64.exe",
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup Snes9x")

        # Setup linux program
        if programs.ShouldProgramBeInstalled("Snes9x", "linux"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetProgramBackupDir("Snes9x", "linux"),
                install_name = "Snes9x",
                install_dir = programs.GetProgramInstallDir("Snes9x", "linux"),
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup Snes9x")
