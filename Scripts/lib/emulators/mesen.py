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

# Mesen emulator
class Mesen(emulatorbase.EmulatorBase):

    # Get name
    def get_name(self):
        return "Mesen"

    # Get platforms
    def get_platforms(self):
        return []

    # Get config
    def get_config(self):
        return {
            "Mesen": {
                "program": {
                    "windows": "Mesen/windows/Mesen.exe",
                    "linux": "Mesen/linux/Mesen.AppImage"
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
        if programs.should_program_be_installed("Mesen", "windows"):
            success = release.download_github_release(
                github_user = "nesdev-org",
                github_repo = "MesenCE",
                starts_with = "Mesen",
                ends_with = "_Windows.zip",
                search_file = "Mesen.exe",
                install_name = "Mesen",
                install_dir = programs.get_program_install_dir("Mesen", "windows"),
                backups_dir = programs.get_program_backup_dir("Mesen", "windows"),
                get_latest = True,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup Mesen")
                return False

        # Build linux program
        if programs.should_program_be_installed("Mesen", "linux"):
            success = release.build_appimage_from_source(
                release_url = "https://github.com/NearlyTRex/Mesen.git",
                output_file = "Mesen-x86_64.AppImage",
                install_name = "Mesen",
                install_dir = programs.get_program_install_dir("Mesen", "linux"),
                backups_dir = programs.get_program_backup_dir("Mesen", "linux"),
                build_cmd = [
                    "export", "PUBLISHFLAGS=-r linux-x64 --no-self-contained false -p:PublishSingleFile=true -p:PublishReadyToRun=true",
                    "&&",
                    "make", "-j", "4", "-O", "LTO=true", "STATICLINK=true", "SYSTEM_LIBEVDEV=false"
                ],
                internal_copies = [
                    {"from": "Source/Mesen/bin/linux-x64/Release/linux-x64/publish/Mesen", "to": "AppImage/usr/bin/Mesen"},
                    {"from": "Source/Mesen/Linux/appimage/Mesen.desktop", "to": "AppImage/Mesen.desktop"},
                    {"from": "Source/Mesen/Linux/appimage/Mesen.48x48.png", "to": "AppImage/Mesen.png"}
                ],
                internal_symlinks = [
                    {"from": "usr/bin/Mesen", "to": "AppRun"}
                ],
                locker_type = setup_params.locker_type,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup Mesen")
                return False
        return True

    # Setup offline
    def setup_offline(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Setup windows program
        if programs.should_program_be_installed("Mesen", "windows"):
            success = release.setup_stored_release(
                archive_dir = programs.get_program_backup_dir("Mesen", "windows"),
                install_name = "Mesen",
                install_dir = programs.get_program_install_dir("Mesen", "windows"),
                search_file = "Mesen.exe",
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup Mesen")
                return False

        # Setup linux program
        if programs.should_program_be_installed("Mesen", "linux"):
            success = release.setup_stored_release(
                archive_dir = programs.get_program_backup_dir("Mesen", "linux"),
                install_name = "Mesen",
                install_dir = programs.get_program_install_dir("Mesen", "linux"),
                search_file = "Mesen.AppImage",
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup Mesen")
                return False
        return True
