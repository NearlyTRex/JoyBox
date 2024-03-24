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

# SheepShaver emulator
class SheepShaver(emulatorbase.EmulatorBase):

    # Get name
    def GetName(self):
        return "SheepShaver"

    # Get platforms
    def GetPlatforms(self):
        return []

    # Get config
    def GetConfig(self):
        return {
            "SheepShaver": {
                "program": {
                    "windows": "SheepShaver/windows/SheepShaver.exe",
                    "linux": "SheepShaver/linux/SheepShaver.AppImage"
                },
                "run_sandboxed": {
                    "windows": False,
                    "linux": False
                }
            }
        }

    # Setup
    def Setup(self, verbose = False, exit_on_failure = False):

        # Download windows program
        if programs.ShouldProgramBeInstalled("SheepShaver", "windows"):
            success = release.DownloadGeneralRelease(
                archive_url = "https://surfdrive.surf.nl/files/index.php/s/kyhQQWmmTB89QrK/download",
                search_file = "SheepShaver.exe",
                install_name = "SheepShaver",
                install_dir = programs.GetProgramInstallDir("SheepShaver", "windows"),
                backups_dir = programs.GetProgramBackupDir("SheepShaver", "windows"),
                release_type = config.release_type_archive,
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup SheepShaver")

        # Download linux program
        if programs.ShouldProgramBeInstalled("SheepShaver", "linux"):
            success = release.DownloadGithubRelease(
                github_user = "Korkman",
                github_repo = "macemu-appimage-builder",
                starts_with = "SheepShaver-x86_64",
                ends_with = ".AppImage",
                search_file = "SheepShaver-x86_64.AppImage",
                install_name = "SheepShaver",
                install_dir = programs.GetProgramInstallDir("SheepShaver", "linux"),
                backups_dir = programs.GetProgramBackupDir("SheepShaver", "linux"),
                release_type = config.release_type_program,
                get_latest = True,
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup SheepShaver")
