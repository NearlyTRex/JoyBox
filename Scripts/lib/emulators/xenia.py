# Imports
import os
import os.path
import sys

# Local imports
import config
import environment
import system
import network
import programs
import launchcommon
import gui
import emulatorbase

# Config files
config_files = {}
config_files["Xenia/windows/portable.txt"] = ""
config_files["Xenia/windows/xenia.config.toml"] = """
[Storage]
content_root = "$GAME_SAVE_DIR"
"""

# Xenia emulator
class Xenia(emulatorbase.EmulatorBase):

    # Get name
    def GetName(self):
        return "Xenia"

    # Get platforms
    def GetPlatforms(self):
        return [
            "Microsoft Xbox 360 GOD",
            "Microsoft Xbox 360 XBLA",
            "Microsoft Xbox 360 XIG",
            "Microsoft Xbox 360"
        ]

    # Get config
    def GetConfig(self):
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

    # Download
    def Download(self, force_downloads = False, verbose = False, exit_on_failure = False):
        if force_downloads or programs.ShouldProgramBeInstalled("Xenia", "windows"):
            network.DownloadLatestGithubRelease(
                github_user = "xenia-project",
                github_repo = "release-builds-windows",
                starts_with = "xenia_master",
                ends_with = "master.zip",
                search_file = "xenia.exe",
                install_name = "Xenia",
                install_dir = programs.GetProgramInstallDir("Xenia", "windows"),
                get_latest = True,
                verbose = verbose,
                exit_on_failure = exit_on_failure)

    # Setup
    def Setup(self, verbose = False, exit_on_failure = False):

        # Create config files
        for config_filename, config_contents in config_files.items():
            system.TouchFile(
                src = os.path.join(environment.GetEmulatorsRootDir(), config_filename),
                contents = config_contents,
                verbose = verbose,
                exit_on_failure = exit_on_failure)

    # Launch
    def Launch(
        self,
        launch_name,
        launch_platform,
        launch_file,
        launch_artwork,
        launch_save_dir,
        launch_general_save_dir,
        launch_capture_type,
        fullscreen = False,
        verbose = False,
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
        launchcommon.SimpleLaunch(
            launch_cmd = launch_cmd,
            launch_name = launch_name,
            launch_platform = launch_platform,
            launch_file = launch_file,
            launch_artwork = launch_artwork,
            launch_save_dir = launch_save_dir,
            launch_capture_type = launch_capture_type,
            verbose = verbose,
            exit_on_failure = exit_on_failure)
