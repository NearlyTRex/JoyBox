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
config_files["Flycast/windows/emu.cfg"] = ""
config_files["Flycast/linux/Flycast.AppImage.home/.config/flycast/emu.cfg"] = ""

# Flycast emulator
class Flycast(base.EmulatorBase):

    # Get name
    def GetName(self):
        return "Flycast"

    # Get platforms
    def GetPlatforms(self):
        return config.flycast_platforms

    # Get config
    def GetConfig(self):
        return {
            "Flycast": {
                "program": {
                    "windows": "Flycast/windows/flycast.exe",
                    "linux": "Flycast/linux/Flycast.AppImage"
                },
                "save_dir": {
                    "windows": "Flycast/windows/data",
                    "linux": "Flycast/linux/Flycast.AppImage.home/.local/share/flycast"
                },
                "config_file": {
                    "windows": "Flycast/windows/emu.cfg",
                    "linux": "Flycast/linux/Flycast.AppImage.home/.config/flycast/emu.cfg"
                },
                "run_sandboxed": {
                    "windows": False,
                    "linux": False
                }
            }
        }

    # Download
    def Download(self, force_downloads = False):
        if force_downloads or programs.ShouldProgramBeInstalled("Flycast", "windows"):
            network.DownloadLatestGithubRelease(
                github_user = "flyinghead",
                github_repo = "flycast",
                starts_with = "flycast-win64",
                ends_with = ".zip",
                search_file = "flycast.exe",
                install_name = "Flycast",
                install_dir = programs.GetProgramInstallDir("Flycast", "windows"),
                get_latest = True,
                verbose = config.default_flag_verbose,
                exit_on_failure = config.default_flag_exit_on_failure)
        if force_downloads or programs.ShouldProgramBeInstalled("Flycast", "linux"):
            network.BuildAppImageFromSource(
                release_url = "https://github.com/flyinghead/flycast.git",
                output_name = "Flycast",
                output_dir = programs.GetProgramInstallDir("Flycast", "linux"),
                build_cmd = [
                    "cmake", "..", "-DCMAKE_BUILD_TYPE=Release",
                    "&&",
                    "make", "-j", "4"
                ],
                build_dir = "Build",
                internal_copies = [
                    {"from": "Source/Build/flycast", "to": "AppImage/usr/bin/flycast"},
                    {"from": "AppImageTool/linux/app.desktop", "to": "AppImage/app.desktop"},
                    {"from": "AppImageTool/linux/icon.png", "to": "AppImage/icon.png"}
                ],
                internal_symlinks = [
                    {"from": "usr/bin/flycast", "to": "AppRun"}
                ],
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
            programs.GetEmulatorProgram("Flycast"),
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
