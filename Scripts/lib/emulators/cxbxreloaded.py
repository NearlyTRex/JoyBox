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

# CxBxReloaded emulator
class CxBxReloaded(emulatorbase.EmulatorBase):

    # Get name
    def get_name(self):
        return "CxBxReloaded"

    # Get platforms
    def get_platforms(self):
        return []

    # Get config
    def get_config(self):
        return {
            "CxBxReloaded": {
                "program": {
                    "windows": "CxBxReloaded/windows/cxbx.exe",
                    "linux": "CxBxReloaded/windows/cxbx.exe"
                },
                "run_sandboxed": {
                    "windows": False,
                    "linux": True
                }
            }
        }

    # Setup
    def setup(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Download windows program
        if programs.ShouldProgramBeInstalled("CxBxReloaded", "windows"):
            success = release.DownloadGithubRelease(
                github_user = "Cxbx-Reloaded",
                github_repo = "Cxbx-Reloaded",
                starts_with = "CxbxReloaded-Release-VS2022",
                ends_with = ".zip",
                search_file = "cxbx.exe",
                install_name = "CxBxReloaded",
                install_dir = programs.GetProgramInstallDir("CxBxReloaded", "windows"),
                backups_dir = programs.GetProgramBackupDir("CxBxReloaded", "windows"),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup CxBxReloaded")
                return False
        return True

    # Setup offline
    def setup_offline(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Setup windows program
        if programs.ShouldProgramBeInstalled("CxBxReloaded", "windows"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetProgramBackupDir("CxBxReloaded", "windows"),
                install_name = "CxBxReloaded",
                install_dir = programs.GetProgramInstallDir("CxBxReloaded", "windows"),
                search_file = "cxbx.exe",
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup CxBxReloaded")
                return False
        return True
