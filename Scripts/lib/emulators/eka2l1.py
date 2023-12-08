# Imports
import os, os.path
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

# Config files
config_files = {}
config_files["EKA2L1/windows/config.yml"] = ""
config_files["EKA2L1/linux/EKA2L1.AppImage.home/.local/share/EKA2L1/config.yml"] = ""

# EKA2L1 emulator
class EKA2L1(base.EmulatorBase):

    # Get name
    def GetName(self):
        return "EKA2L1"

    # Get platforms
    def GetPlatforms(self):
        return [
            "Nokia N-Gage"
        ]

    # Get config
    def GetConfig(self):
        return {
            "EKA2L1": {
                "program": {
                    "windows": "EKA2L1/windows/eka2l1_qt.exe",
                    "linux": "EKA2L1/linux/EKA2L1.AppImage"
                },
                "save_dir": {
                    "windows": None,
                    "linux": None
                },
                "config_file": {
                    "windows": "EKA2L1/windows/config.yml",
                    "linux": "EKA2L1/linux/EKA2L1.AppImage.home/.local/share/EKA2L1/config.yml"
                },
                "run_sandboxed": {
                    "windows": False,
                    "linux": False
                }
            }
        }

    # Download
    def Download(self, force_downloads = False, verbose = False, exit_on_failure = False):
        if force_downloads or programs.ShouldProgramBeInstalled("EKA2L1", "windows"):
            network.DownloadLatestGithubRelease(
                github_user = "EKA2L1",
                github_repo = "EKA2L1",
                starts_with = "windows-latest",
                ends_with = ".zip",
                search_file = "eka2l1_qt.exe",
                install_name = "EKA2L1",
                install_dir = programs.GetProgramInstallDir("EKA2L1", "windows"),
                get_latest = True,
                verbose = verbose,
                exit_on_failure = exit_on_failure)
        if force_downloads or programs.ShouldProgramBeInstalled("EKA2L1", "linux"):
            network.DownloadLatestGithubRelease(
                github_user = "EKA2L1",
                github_repo = "EKA2L1",
                starts_with = "ubuntu-latest",
                ends_with = ".AppImage",
                search_file = "ubuntu-latest.AppImage",
                install_name = "EKA2L1",
                install_dir = programs.GetProgramInstallDir("EKA2L1", "linux"),
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
        verbose = False,
        exit_on_failure = False):

        # Get launch command
        launch_cmd = [
            programs.GetEmulatorProgram("EKA2L1"),
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
            launch_capture_type = launch_capture_type,
            verbose = verbose,
            exit_on_failure = exit_on_failure)
