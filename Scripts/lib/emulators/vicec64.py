# Imports
import os
import os.path
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
import gui
import emulatorcommon
import emulatorbase

# Config files
config_files = {}
config_files["VICE-C64/windows/sdl-vice.ini"] = ""
config_files["VICE-C64/linux/VICE-C64.AppImage.home/.config/vice/vicerc"] = ""

# System files
system_files = {}

# ViceC64 emulator
class ViceC64(emulatorbase.EmulatorBase):

    # Get name
    def get_name(self):
        return "VICE-C64"

    # Get platforms
    def get_platforms(self):
        return [
            config.Platform.OTHER_COMMODORE_64
        ]

    # Get config
    def get_config(self):
        return {
            "VICE-C64": {
                "program": {
                    "windows": "VICE-C64/windows/x64sc.exe",
                    "linux": "VICE-C64/linux/VICE-C64.AppImage"
                },
                "save_dir": {
                    "windows": None,
                    "linux": None
                },
                "config_file": {
                    "windows": "VICE-C64/windows/sdl-vice.ini",
                    "linux": "VICE-C64/linux/VICE-C64.AppImage.home/.config/vice/vicerc"
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
        if programs.should_program_be_installed("VICE-C64", "windows"):
            success = release.download_github_release(
                github_user = "VICE-Team",
                github_repo = "svn-mirror",
                starts_with = "SDL2VICE",
                ends_with = "win64.zip",
                search_file = "x64sc.exe",
                install_name = "VICE-C64",
                install_dir = programs.get_program_install_dir("VICE-C64", "windows"),
                backups_dir = programs.get_program_backup_dir("VICE-C64", "windows"),
                get_latest = True,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup VICE-C64")
                return False

        # Download linux program
        if programs.should_program_be_installed("VICE-C64", "linux"):
            success = release.build_appimage_from_source(
                release_url = "https://github.com/NearlyTRex/ViceC64.git",
                output_file = "App-x86_64.AppImage",
                install_name = "VICE-C64",
                install_dir = programs.get_program_install_dir("VICE-C64", "linux"),
                backups_dir = programs.get_program_backup_dir("VICE-C64", "linux"),
                build_cmd = [
                    "cd", "vice",
                    "&&",
                    "./autogen.sh",
                    "&&",
                    "./configure", "--disable-html-docs", "--enable-pdf-docs=no",
                    "&&",
                    "make", "-j", "4"
                ],
                internal_copies = [
                    {"from": "Source/vice/data", "to": "AppImage/usr/bin"},
                    {"from": "Source/vice/src/x64sc", "to": "AppImage/usr/bin/x64sc"},
                    {"from": "AppImageTool/linux/app.desktop", "to": "AppImage/app.desktop"},
                    {"from": "AppImageTool/linux/icon.svg", "to": "AppImage/icon.svg"}
                ],
                internal_symlinks = [
                    {"from": "usr/bin/x64sc", "to": "AppRun"}
                ],
                locker_type = setup_params.locker_type,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup VICE-C64")
                return False
        return True

    # Setup offline
    def setup_offline(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Setup windows program
        if programs.should_program_be_installed("VICE-C64", "windows"):
            success = release.setup_stored_release(
                archive_dir = programs.get_program_backup_dir("VICE-C64", "windows"),
                install_name = "VICE-C64",
                install_dir = programs.get_program_install_dir("VICE-C64", "windows"),
                search_file = "x64sc.exe",
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup VICE-C64")
                return False

        # Setup linux program
        if programs.should_program_be_installed("VICE-C64", "linux"):
            success = release.setup_stored_release(
                archive_dir = programs.get_program_backup_dir("VICE-C64", "linux"),
                install_name = "VICE-C64",
                install_dir = programs.get_program_install_dir("VICE-C64", "linux"),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup VICE-C64")
                return False
        return True

    # Configure
    def configure(self, setup_params = None):
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
                logger.log_error("Could not setup VICE-C64 config files")
                return False
        return True

    # Launch
    def launch(
        self,
        game_info,
        capture_type = None,
        capture_file = None,
        fullscreen = False,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Get launch command
        launch_cmd = [
            programs.get_emulator_program("VICE-C64"),
            config.token_game_file
        ]

        # Launch game
        return emulatorcommon.SimpleLaunch(
            game_info = game_info,
            launch_cmd = launch_cmd,
            capture_type = capture_type,
            capture_file = capture_file,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
