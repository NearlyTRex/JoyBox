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

# SheepShaver emulator
class SheepShaver(emulatorbase.EmulatorBase):

    # Get name
    def get_name(self):
        return "SheepShaver"

    # Get platforms
    def get_platforms(self):
        return []

    # Get config
    def get_config(self):
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
    def setup(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Download windows program
        if programs.ShouldProgramBeInstalled("SheepShaver", "windows"):
            success = release.DownloadGeneralRelease(
                archive_url = "https://surfdrive.surf.nl/files/index.php/s/kyhQQWmmTB89QrK/download",
                search_file = "SheepShaver.exe",
                install_name = "SheepShaver",
                install_dir = programs.GetProgramInstallDir("SheepShaver", "windows"),
                backups_dir = programs.GetProgramBackupDir("SheepShaver", "windows"),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup SheepShaver")
                return False

        # Download linux program
        if programs.ShouldProgramBeInstalled("SheepShaver", "linux"):
            success = release.DownloadGithubRelease(
                github_user = "Korkman",
                github_repo = "macemu-appimage-builder",
                starts_with = "SheepShaver-x86_64",
                ends_with = ".AppImage",
                install_name = "SheepShaver",
                install_dir = programs.GetProgramInstallDir("SheepShaver", "linux"),
                backups_dir = programs.GetProgramBackupDir("SheepShaver", "linux"),
                get_latest = True,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup SheepShaver")
                return False
        return True

    # Setup offline
    def setup_offline(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Setup windows program
        if programs.ShouldProgramBeInstalled("SheepShaver", "windows"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetProgramBackupDir("SheepShaver", "windows"),
                install_name = "SheepShaver",
                install_dir = programs.GetProgramInstallDir("SheepShaver", "windows"),
                search_file = "SheepShaver.exe",
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup SheepShaver")
                return False

        # Setup linux program
        if programs.ShouldProgramBeInstalled("SheepShaver", "linux"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetProgramBackupDir("SheepShaver", "linux"),
                install_name = "SheepShaver",
                install_dir = programs.GetProgramInstallDir("SheepShaver", "linux"),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup SheepShaver")
                return False
        return True
