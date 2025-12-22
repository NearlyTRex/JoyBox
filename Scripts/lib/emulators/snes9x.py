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

# Snes9x emulator
class Snes9x(emulatorbase.EmulatorBase):

    # Get name
    def get_name(self):
        return "Snes9x"

    # Get platforms
    def get_platforms(self):
        return []

    # Get config
    def get_config(self):
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
    def setup(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

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
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup Snes9x")
                return False

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
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup Snes9x")
                return False
        return True

    # Setup offline
    def setup_offline(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Setup windows program
        if programs.ShouldProgramBeInstalled("Snes9x", "windows"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetProgramBackupDir("Snes9x", "windows"),
                install_name = "Snes9x",
                install_dir = programs.GetProgramInstallDir("Snes9x", "windows"),
                search_file = "snes9x-x64.exe",
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup Snes9x")
                return False

        # Setup linux program
        if programs.ShouldProgramBeInstalled("Snes9x", "linux"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetProgramBackupDir("Snes9x", "linux"),
                install_name = "Snes9x",
                install_dir = programs.GetProgramInstallDir("Snes9x", "linux"),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup Snes9x")
                return False
        return True
