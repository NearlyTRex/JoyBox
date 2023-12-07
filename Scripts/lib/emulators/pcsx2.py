# Imports
import os
import os.path
import sys

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.append(lib_folder)
import config
import environment
import system
import network
import programs
import launchcommon
import gui

# Local imports
from . import base

# PCSX2 emulator
class PCSX2(base.EmulatorBase):

    # Get name
    def GetName():
        return "PCSX2"

    # Get platforms
    def GetPlatforms():
        return config.pcsx2_platforms

    # Get config
    def GetConfig():
        return {
            "PCSX2": {
                "program": {
                    "windows": "PCSX2/windows/pcsx2-qt.exe",
                    "linux": "PCSX2/linux/PCSX2.AppImage"
                },
                "save_dir": {
                    "windows": "PCSX2/windows/memcards",
                    "linux": "PCSX2/linux/PCSX2.AppImage.home/.config/PCSX2/memcards"
                },
                "setup_dir": {
                    "windows": "PCSX2/windows",
                    "linux": "PCSX2/linux/PCSX2.AppImage.home/.config/PCSX2"
                },
                "config_file": {
                    "windows": "PCSX2/windows/inis/PCSX2.ini",
                    "linux": "PCSX2/linux/PCSX2.AppImage.home/.config/PCSX2/inis/PCSX2.ini"
                },
                "run_sandboxed": {
                    "windows": False,
                    "linux": False
                }
            }
        }

    # Download
    def Download(force_downloads = False):
        if force_downloads or programs.ShouldProgramBeInstalled("PCSX2", "windows"):
            network.DownloadLatestGithubRelease(
                github_user = "PCSX2",
                github_repo = "pcsx2",
                starts_with = "pcsx2",
                ends_with = "windows-x64-Qt.7z",
                search_file = "pcsx2-qt.exe",
                install_name = "PCSX2",
                install_dir = programs.GetProgramInstallDir("PCSX2", "windows"),
                verbose = config.default_flag_verbose,
                exit_on_failure = config.default_flag_exit_on_failure)
        if force_downloads or programs.ShouldProgramBeInstalled("PCSX2", "linux"):
            network.DownloadLatestGithubRelease(
                github_user = "PCSX2",
                github_repo = "pcsx2",
                starts_with = "pcsx2",
                ends_with = ".AppImage",
                search_file = "PCSX2.AppImage",
                install_name = "PCSX2",
                install_dir = programs.GetProgramInstallDir("PCSX2", "linux"),
                verbose = config.default_flag_verbose,
                exit_on_failure = config.default_flag_exit_on_failure)

    # Setup
    def Setup():
        system.CopyContents(
            src = environment.GetSyncedGameEmulatorSetupDir("PCSX2"),
            dest = programs.GetEmulatorPathConfigValue("PCSX2", "setup_dir", "linux"),
            skip_existing = True,
            verbose = config.default_flag_verbose,
            exit_on_failure = config.default_flag_exit_on_failure)
        system.CopyContents(
            src = environment.GetSyncedGameEmulatorSetupDir("PCSX2"),
            dest = programs.GetEmulatorPathConfigValue("PCSX2", "setup_dir", "windows"),
            skip_existing = True,
            verbose = config.default_flag_verbose,
            exit_on_failure = config.default_flag_exit_on_failure)

    # Launch
    def Launch(
        launch_name,
        launch_platform,
        launch_file,
        launch_artwork,
        launch_save_dir,
        launch_general_save_dir,
        launch_capture_type):

        # Get launch command
        launch_cmd = [
            programs.GetEmulatorProgram("PCSX2"),
            config.token_game_file
        ]

        # Launch game
        launchcommon.SimpleLaunch(
            launch_cmd = launch_cmd,
            launch_name = launch_name,
            launch_platform = launch_platform,
            launch_file = launch_file,
            launch_artwork = launch_artwork,
            launch_save_dir = launch_save_dir,
            launch_capture_type = launch_capture_type)
