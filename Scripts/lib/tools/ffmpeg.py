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

# FFMpeg tool
class FFMpeg(toolbase.ToolBase):

    # Get name
    def get_name(self):
        return "FFMpeg"

    # Get config
    def get_config(self):
        return {
            "FFMpeg": {
                "program": {
                    "windows": "FFMpeg/windows/ffmpeg.exe",
                    "linux": "FFMpeg/linux/ffmpeg"
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
        if programs.should_program_be_installed("FFMpeg", "windows"):
            success = release.DownloadGithubRelease(
                github_user = "BtbN",
                github_repo = "FFmpeg-Builds",
                starts_with = "ffmpeg-master-latest",
                ends_with = "win64-gpl.zip",
                search_file = "ffmpeg.exe",
                install_name = "FFMpeg",
                install_dir = programs.get_program_install_dir("FFMpeg", "windows"),
                backups_dir = programs.get_program_backup_dir("FFMpeg", "windows"),
                install_files = ["ffmpeg.exe"],
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup FFMpeg")
                return False

        # Download linux program
        if programs.should_program_be_installed("FFMpeg", "linux"):
            success = release.DownloadGithubRelease(
                github_user = "BtbN",
                github_repo = "FFmpeg-Builds",
                starts_with = "ffmpeg-master-latest",
                ends_with = "linux64-gpl.tar.xz",
                search_file = "ffmpeg",
                install_name = "FFMpeg",
                install_dir = programs.get_program_install_dir("FFMpeg", "linux"),
                backups_dir = programs.get_program_backup_dir("FFMpeg", "linux"),
                install_files = ["ffmpeg"],
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup FFMpeg")
                return False
        return True

    # Setup offline
    def setup_offline(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Setup windows program
        if programs.should_program_be_installed("FFMpeg", "windows"):
            success = release.SetupStoredRelease(
                archive_dir = programs.get_program_backup_dir("FFMpeg", "windows"),
                install_name = "FFMpeg",
                install_dir = programs.get_program_install_dir("FFMpeg", "windows"),
                search_file = "ffmpeg.exe",
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup FFMpeg")
                return False

        # Setup linux program
        if programs.should_program_be_installed("FFMpeg", "linux"):
            success = release.SetupStoredRelease(
                archive_dir = programs.get_program_backup_dir("FFMpeg", "linux"),
                install_name = "FFMpeg",
                install_dir = programs.get_program_install_dir("FFMpeg", "linux"),
                search_file = "ffmpeg",
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup FFMpeg")
                return False
        return True
