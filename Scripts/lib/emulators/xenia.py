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
config_files["Xenia/windows/portable.txt"] = ""
config_files["Xenia/windows/xenia.config.toml"] = """
[Storage]
content_root = "GAME_SAVE_DIR"
"""

# System files
system_files = {}

# Xenia emulator
class Xenia(emulatorbase.EmulatorBase):

    # Get name
    def get_name(self):
        return "Xenia"

    # Get platforms
    def get_platforms(self):
        return [
            config.Platform.MICROSOFT_XBOX_360,
            config.Platform.MICROSOFT_XBOX_360_GOD,
            config.Platform.MICROSOFT_XBOX_360_XBLA,
            config.Platform.MICROSOFT_XBOX_360_XIG
        ]

    # Get config
    def get_config(self):
        return {
            "Xenia": {
                "program": {
                    "windows": "Xenia/windows/xenia.exe",
                    "linux": "Xenia/windows/xenia.exe"
                },
                "save_dir": {
                    "windows": "Xenia/windows/content",
                    "linux": "Xenia/windows/content"
                },
                "config_file": {
                    "windows": "Xenia/windows/xenia.config.toml",
                    "linux": "Xenia/windows/xenia.config.toml"
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
        if programs.ShouldProgramBeInstalled("Xenia", "windows"):
            success = release.DownloadGithubRelease(
                github_user = "xenia-project",
                github_repo = "release-builds-windows",
                starts_with = "xenia_master",
                ends_with = "master.zip",
                search_file = "xenia.exe",
                install_name = "Xenia",
                install_dir = programs.GetProgramInstallDir("Xenia", "windows"),
                backups_dir = programs.GetProgramBackupDir("Xenia", "windows"),
                get_latest = True,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup Xenia")
                return False
        return True

    # Setup offline
    def setup_offline(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Setup windows program
        if programs.ShouldProgramBeInstalled("Xenia", "windows"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetProgramBackupDir("Xenia", "windows"),
                install_name = "Xenia",
                install_dir = programs.GetProgramInstallDir("Xenia", "windows"),
                search_file = "xenia.exe",
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup Xenia")
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
                logger.log_error("Could not setup Xenia config files")
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
            programs.GetEmulatorProgram("Xenia"),
            config.token_game_file
        ]
        if fullscreen:
            launch_cmd += [
                "--fullscreen=true"
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
