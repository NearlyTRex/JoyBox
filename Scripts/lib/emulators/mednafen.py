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

# Config files
config_files = {}
config_files["Mednafen/windows/mednafen.cfg"] = ""
config_files["Mednafen/linux/Mednafen.AppImage.home/.mednafen/mednafen.cfg"] = ""

# Mednafen emulator
class Mednafen(base.EmulatorBase):

    # Get name
    def GetName(self):
        return "Mednafen"

    # Get platforms
    def GetPlatforms(self):
        return config.mednafen_platforms

    # Get config
    def GetConfig(self):
        return {
            "Mednafen": {
                "program": {
                    "windows": "Mednafen/windows/mednafen.exe",
                    "linux": "Mednafen/linux/Mednafen.AppImage"
                },
                "save_dir": {
                    "windows": "Mednafen/windows/sav",
                    "linux": "Mednafen/linux/Mednafen.AppImage.home/.mednafen/sav"
                },
                "setup_dir": {
                    "windows": "Mednafen/windows",
                    "linux": "Mednafen/linux/Mednafen.AppImage.home/.mednafen"
                },
                "config_file": {
                    "windows": "Mednafen/windows/mednafen.cfg",
                    "linux": "Mednafen/linux/Mednafen.AppImage.home/.mednafen/mednafen.cfg"
                },
                "run_sandboxed": {
                    "windows": False,
                    "linux": False
                }
            }
        }

    # Download
    def Download(self, force_downloads = False):
        if force_downloads or programs.ShouldProgramBeInstalled("Mednafen", "windows"):
            network.DownloadLatestWebpageRelease(
                webpage_url = "https://mednafen.github.io/",
                starts_with = "https://mednafen.github.io/releases/files/mednafen",
                ends_with = "UNSTABLE-win64.zip",
                search_file = "mednafen.exe",
                install_name = "Mednafen",
                install_dir = programs.GetProgramInstallDir("Mednafen", "windows"),
                verbose = config.default_flag_verbose,
                exit_on_failure = config.default_flag_exit_on_failure)
        if force_downloads or programs.ShouldProgramBeInstalled("Mednafen", "linux"):
            network.BuildAppImageFromSource(
                webpage_url = "https://mednafen.github.io/",
                starts_with = "https://mednafen.github.io/releases/files/mednafen",
                ends_with = "UNSTABLE.tar.xz",
                output_name = "Mednafen",
                output_dir = programs.GetProgramInstallDir("Mednafen", "linux"),
                build_cmd = [
                    "cd", "mednafen",
                    "&&",
                    "./configure",
                    "&&",
                    "make", "-j", "4"
                ],
                internal_copies = [
                    {"from": "Source/mednafen/src/mednafen", "to": "AppImage/usr/bin/mednafen"},
                    {"from": "AppImageTool/linux/app.desktop", "to": "AppImage/app.desktop"},
                    {"from": "AppImageTool/linux/icon.png", "to": "AppImage/icon.png"}
                ],
                internal_symlinks = [
                    {"from": "usr/bin/mednafen", "to": "AppRun"}
                ],
                verbose = config.default_flag_verbose,
                exit_on_failure = config.default_flag_exit_on_failure)

    # Setup
    def Setup(self):
        system.CopyContents(
            src = environment.GetSyncedGameEmulatorSetupDir("Mednafen"),
            dest = programs.GetEmulatorPathConfigValue("Mednafen", "setup_dir", "linux"),
            skip_existing = True,
            verbose = config.default_flag_verbose,
            exit_on_failure = config.default_flag_exit_on_failure)
        system.CopyContents(
            src = environment.GetSyncedGameEmulatorSetupDir("Mednafen"),
            dest = programs.GetEmulatorPathConfigValue("Mednafen", "setup_dir", "windows"),
            skip_existing = True,
            verbose = config.default_flag_verbose,
            exit_on_failure = config.default_flag_exit_on_failure)

    # Launch
    def Launch(
        self,
        launch_name,
        launch_platform,
        launch_file,
        launch_artwork,
        launch_save_dir,
        launch_general_save_dir,
        launch_capture_type):

        # Get launch command
        launch_cmd = [
            programs.GetEmulatorProgram("Mednafen"),
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
