# Imports
import os, os.path
import sys

# Local imports
import config
import system
import logger
import network
import release
import programs
import toolbase

# Config files
config_files = {}

# XorrISO tool
class XorrISO(toolbase.ToolBase):

    # Get name
    def GetName(self):
        return "XorrISO"

    # Get config
    def GetConfig(self):
        return {
            "XorrISO": {
                "program": {
                    "windows": "XorrISO/windows/xorriso.exe",
                    "linux": "XorrISO/linux/XorrISO.AppImage"
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
        if programs.ShouldProgramBeInstalled("XorrISO", "windows"):
            success = network.DownloadGithubRepository(
                github_user = "NearlyTRex",
                github_repo = "XorrISOWindows",
                output_dir = programs.GetProgramInstallDir("XorrISO", "windows"),
                recursive = True,
                clean = True,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup XorrISO")
                return False
            success = network.ArchiveGithubRepository(
                github_user = "NearlyTRex",
                github_repo = "XorrISOWindows",
                output_dir = programs.GetProgramBackupDir("XorrISO", "windows"),
                recursive = True,
                clean = True,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup XorrISO")
                return False

        # Build linux program
        if programs.ShouldProgramBeInstalled("XorrISO", "linux"):
            success = release.BuildAppImageFromSource(
                release_url = "https://ftp.gnu.org/gnu/xorriso/xorriso-1.5.2.tar.gz",
                output_file = "App-x86_64.AppImage",
                install_name = "XorrISO",
                install_dir = programs.GetProgramInstallDir("XorrISO", "linux"),
                backups_dir = programs.GetProgramBackupDir("XorrISO", "linux"),
                build_cmd = [
                    "cd", "xorriso-1.5.2",
                    "./bootstrap",
                    "&&",
                    "./configure",
                    "&&",
                    "make", "-j", "4"
                ],
                internal_copies = [
                    {"from": "Source/xorriso-1.5.2/xorriso/xorriso", "to": "AppImage/usr/bin/xorriso"},
                    {"from": "AppImageTool/linux/app.desktop", "to": "AppImage/app.desktop"},
                    {"from": "AppImageTool/linux/icon.svg", "to": "AppImage/icon.svg"}
                ],
                internal_symlinks = [
                    {"from": "usr/bin/xorriso", "to": "AppRun"}
                ],
                locker_type = setup_params.locker_type,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup XorrISO")
                return False
        return True

    # Setup offline
    def SetupOffline(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Setup windows program
        if programs.ShouldProgramBeInstalled("XorrISO", "windows"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetProgramBackupDir("XorrISO", "windows"),
                install_name = "XorrISO",
                install_dir = programs.GetProgramInstallDir("XorrISO", "windows"),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup XorrISO")
                return False

        # Setup linux program
        if programs.ShouldProgramBeInstalled("XorrISO", "linux"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetProgramBackupDir("XorrISO", "linux"),
                install_name = "XorrISO",
                install_dir = programs.GetProgramInstallDir("XorrISO", "linux"),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup XorrISO")
                return False
        return True
