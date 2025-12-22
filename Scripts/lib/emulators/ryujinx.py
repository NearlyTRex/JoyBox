# Imports
import os, os.path
import sys

# Local imports
import config
import environment
import fileops
import system
import logger
import paths
import release
import programs
import emulatorbase

# Config files
config_files = {}
config_files["Ryujinx/windows/portable/Config.json"] = ""
config_files["Ryujinx/linux/portable/Config.json"] = ""

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
                    "linux": "Ryujinx/linux/Ryujinx"
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
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup Ryujinx")
                return False

        # Download linux program
        if programs.ShouldProgramBeInstalled("Ryujinx", "linux"):
            success = release.DownloadGithubRelease(
                github_user = "Ryujinx",
                github_repo = "release-channel-master",
                starts_with = "ryujinx",
                ends_with = "linux_x64.tar.gz",
                search_file = "Ryujinx.sh",
                install_name = "Ryujinx",
                install_dir = programs.GetProgramInstallDir("Ryujinx", "linux"),
                backups_dir = programs.GetProgramBackupDir("Ryujinx", "linux"),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup Ryujinx")
                return False
        return True

    # Setup offline
    def SetupOffline(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Setup windows program
        if programs.ShouldProgramBeInstalled("Ryujinx", "windows"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetProgramBackupDir("Ryujinx", "windows"),
                install_name = "Ryujinx",
                install_dir = programs.GetProgramInstallDir("Ryujinx", "windows"),
                search_file = "Ryujinx.exe",
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup Ryujinx")
                return False

        # Setup linux program
        if programs.ShouldProgramBeInstalled("Ryujinx", "linux"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetProgramBackupDir("Ryujinx", "linux"),
                install_name = "Ryujinx",
                install_dir = programs.GetProgramInstallDir("Ryujinx", "linux"),
                search_file = "Ryujinx.sh",
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup Ryujinx")
                return False
        return True

    # Configure
    def Configure(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Create config files
        for config_filename, config_contents in config_files.items():
            success = fileops.touch_file(
                src = paths.join_paths(environment.get_emulators_root_dir(), config_filename),
                contents = config_contents.strip(),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup Ryujinx config files")
                return False
        return True
