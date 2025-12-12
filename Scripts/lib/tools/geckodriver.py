# Imports
import os, os.path
import sys

# Local imports
import config
import system
import release
import programs
import toolbase

# Config files
config_files = {}

# GeckoDriver tool
class GeckoDriver(toolbase.ToolBase):

    # Get name
    def GetName(self):
        return "GeckoDriver"

    # Get config
    def GetConfig(self):
        return {
            "GeckoDriver": {
                "program": {
                    "windows": "GeckoDriver/windows/geckodriver.exe",
                    "linux": "GeckoDriver/linux/geckodriver"
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
        if programs.ShouldProgramBeInstalled("GeckoDriver", "windows"):
            success = release.DownloadGithubRelease(
                github_user = "mozilla",
                github_repo = "geckodriver",
                starts_with = "geckodriver",
                ends_with = "win32.zip",
                search_file = "geckodriver.exe",
                install_name = "GeckoDriver",
                install_dir = programs.GetProgramInstallDir("GeckoDriver", "windows"),
                backups_dir = programs.GetProgramBackupDir("GeckoDriver", "windows"),
                install_files = ["geckodriver.exe"],
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                system.LogError("Could not setup GeckoDriver")
                return False

        # Download linux program
        if programs.ShouldProgramBeInstalled("GeckoDriver", "linux"):
            success = release.DownloadGithubRelease(
                github_user = "mozilla",
                github_repo = "geckodriver",
                starts_with = "geckodriver",
                ends_with = "linux64.tar.gz",
                search_file = "geckodriver",
                install_name = "GeckoDriver",
                install_dir = programs.GetProgramInstallDir("GeckoDriver", "linux"),
                backups_dir = programs.GetProgramBackupDir("GeckoDriver", "linux"),
                install_files = ["geckodriver"],
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                system.LogError("Could not setup GeckoDriver")
                return False
        return True

    # Setup offline
    def SetupOffline(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Setup windows program
        if programs.ShouldProgramBeInstalled("GeckoDriver", "windows"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetProgramBackupDir("GeckoDriver", "windows"),
                install_name = "GeckoDriver",
                install_dir = programs.GetProgramInstallDir("GeckoDriver", "windows"),
                search_file = "geckodriver.exe",
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                system.LogError("Could not setup GeckoDriver")
                return False

        # Setup linux program
        if programs.ShouldProgramBeInstalled("GeckoDriver", "linux"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetProgramBackupDir("GeckoDriver", "linux"),
                install_name = "GeckoDriver",
                install_dir = programs.GetProgramInstallDir("GeckoDriver", "linux"),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                system.LogError("Could not setup GeckoDriver")
                return False
        return True
