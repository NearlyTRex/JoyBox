# Imports
import os, os.path
import sys

# Local imports
import config
import system
import logger
import release
import programs
import toolbase

# Config files
config_files = {}

# JDupes tool
class JDupes(toolbase.ToolBase):

    # Get name
    def GetName(self):
        return "JDupes"

    # Get config
    def GetConfig(self):
        return {
            "JDupes": {
                "program": {
                    "windows": "JDupes/windows/jdupes.exe",
                    "linux": "JDupes/linux/jdupes"
                },
                "run_sandboxed": {
                    "windows": False,
                    "linux": False
                }
            }
        }

    # Setup
    def Setup(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Download windows program
        if programs.ShouldProgramBeInstalled("JDupes", "windows"):
            success = release.DownloadGithubRelease(
                github_user = "NearlyTRex",
                github_repo = "JDupes",
                starts_with = "jdupes",
                ends_with = "win64.zip",
                search_file = "jdupes.exe",
                install_name = "JDupes",
                install_dir = programs.GetProgramInstallDir("JDupes", "windows"),
                backups_dir = programs.GetProgramBackupDir("JDupes", "windows"),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup JDupes")
                return False

        # Download linux program
        if programs.ShouldProgramBeInstalled("JDupes", "linux"):
            success = release.DownloadGithubRelease(
                github_user = "NearlyTRex",
                github_repo = "JDupes",
                starts_with = "jdupes",
                ends_with = "linux-x86_64.pkg.tar.xz",
                search_file = "jdupes",
                install_name = "JDupes",
                install_dir = programs.GetProgramInstallDir("JDupes", "linux"),
                backups_dir = programs.GetProgramBackupDir("JDupes", "linux"),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup JDupes")
                return False
        return True

    # Setup offline
    def SetupOffline(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Setup windows program
        if programs.ShouldProgramBeInstalled("JDupes", "windows"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetProgramBackupDir("JDupes", "windows"),
                install_name = "JDupes",
                install_dir = programs.GetProgramInstallDir("JDupes", "windows"),
                search_file = "jdupes.exe",
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup JDupes")
                return False

        # Setup linux program
        if programs.ShouldProgramBeInstalled("JDupes", "linux"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetProgramBackupDir("JDupes", "linux"),
                install_name = "JDupes",
                install_dir = programs.GetProgramInstallDir("JDupes", "linux"),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup JDupes")
                return False
        return True
