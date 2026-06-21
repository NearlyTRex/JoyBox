# Imports
import os, os.path
import sys

# Local imports
import joybox.config as config
import joybox.environment as environment
import joybox.system as system
import joybox.logger as logger
import joybox.release as release
import joybox.programs as programs
import joybox.emulatorbase as emulatorbase

# Config files
config_files = {}

# System files
system_files = {}

# Stella emulator
class Stella(emulatorbase.EmulatorBase):

    # Get name
    def get_name(self):
        return "Stella"

    # Get platforms
    def get_platforms(self):
        return []

    # Get config
    def get_config(self):
        return {
            "Stella": {
                "program": {
                    "windows": "Stella/windows/Stella.exe",
                    "linux": "Stella/linux/Stella.AppImage"
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
        if programs.should_program_be_installed("Stella", "windows"):
            success = release.download_github_release(
                github_user = "stella-emu",
                github_repo = "stella",
                starts_with = "Stella",
                ends_with = "windows.zip",
                search_file = "64-bit/Stella.exe",
                install_name = "Stella",
                install_dir = programs.get_program_install_dir("Stella", "windows"),
                backups_dir = programs.get_program_backup_dir("Stella", "windows"),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup Stella")
                return False

        # Build linux program
        if programs.should_program_be_installed("Stella", "linux"):
            success = release.build_appimage_from_source(
                release_url = "https://github.com/NearlyTRex/Stella.git",
                release_branch = "7.0",
                output_file = "Stella-x86_64.AppImage",
                install_name = "Stella",
                install_dir = programs.get_program_install_dir("Stella", "linux"),
                backups_dir = programs.get_program_backup_dir("Stella", "linux"),
                build_cmd = [
                    "./configure",
                    "&&",
                    "make", "-j", "4"
                ],
                internal_copies = [
                    {"from": "Source/Stella/stella", "to": "AppImage/usr/bin/stella"},
                    {"from": "Source/Stella/src/os/unix/stella.desktop", "to": "AppImage/stella.desktop"},
                    {"from": "Source/Stella/src/common/stella.png", "to": "AppImage/stella.png"}
                ],
                internal_symlinks = [
                    {"from": "usr/bin/stella", "to": "AppRun"}
                ],
                locker_type = setup_params.locker_type,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup Stella")
                return False
        return True

    # Setup offline
    def setup_offline(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Setup windows program
        if programs.should_program_be_installed("Stella", "windows"):
            success = release.setup_stored_release(
                archive_dir = programs.get_program_backup_dir("Stella", "windows"),
                install_name = "Stella",
                install_dir = programs.get_program_install_dir("Stella", "windows"),
                search_file = "64-bit/Stella.exe",
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup Stella")
                return False

        # Setup linux program
        if programs.should_program_be_installed("Stella", "linux"):
            success = release.setup_stored_release(
                archive_dir = programs.get_program_backup_dir("Stella", "linux"),
                install_name = "Stella",
                install_dir = programs.get_program_install_dir("Stella", "linux"),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup Stella")
                return False
        return True
