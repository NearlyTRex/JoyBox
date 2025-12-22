# Imports
import os, os.path
import sys

# Local imports
import config
import system
import logger
import environment
import release
import programs
import toolbase

# Config files
config_files = {}

# YtDlp tool
class YtDlp(toolbase.ToolBase):

    # Get name
    def get_name(self):
        return "YtDlp"

    # Get config
    def get_config(self):
        return {
            "YtDlp": {
                "program": {
                    "windows": "YtDlp/windows/yt-dlp.exe",
                    "linux": "YtDlp/linux/yt-dlp_linux"
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
        if programs.should_program_be_installed("YtDlp", "windows"):
            success = release.DownloadGithubRelease(
                github_user = "yt-dlp",
                github_repo = "yt-dlp",
                starts_with = "yt-dlp",
                ends_with = ".exe",
                search_file = "yt-dlp.exe",
                install_name = "YtDlp",
                install_dir = programs.get_program_install_dir("YtDlp", "windows"),
                backups_dir = programs.get_program_backup_dir("YtDlp", "windows"),
                install_files = ["yt-dlp.exe"],
                get_latest = True,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup YtDlp")
                return False

        # Download linux program
        if programs.should_program_be_installed("YtDlp", "linux"):
            success = release.DownloadGithubRelease(
                github_user = "yt-dlp",
                github_repo = "yt-dlp",
                starts_with = "yt-dlp",
                ends_with = "_linux",
                search_file = "yt-dlp_linux",
                install_name = "YtDlp",
                install_dir = programs.get_program_install_dir("YtDlp", "linux"),
                backups_dir = programs.get_program_backup_dir("YtDlp", "linux"),
                install_files = ["yt-dlp_linux"],
                release_type = config.ReleaseType.PROGRAM,
                chmod_files = [
                    {
                        "file": "yt-dlp_linux",
                        "perms": 755
                    }
                ],
                get_latest = True,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup YtDlp")
                return False
        return True

    # Setup offline
    def setup_offline(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Setup windows program
        if programs.should_program_be_installed("YtDlp", "windows"):
            success = release.SetupStoredRelease(
                archive_dir = programs.get_program_backup_dir("YtDlp", "windows"),
                install_name = "YtDlp",
                install_dir = programs.get_program_install_dir("YtDlp", "windows"),
                search_file = "yt-dlp.exe",
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup YtDlp")
                return False

        # Setup linux program
        if programs.should_program_be_installed("YtDlp", "linux"):
            success = release.SetupStoredRelease(
                archive_dir = programs.get_program_backup_dir("YtDlp", "linux"),
                install_name = "YtDlp",
                install_dir = programs.get_program_install_dir("YtDlp", "linux"),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup YtDlp")
                return False
        return True
