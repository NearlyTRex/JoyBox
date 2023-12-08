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
config_files["FS-UAE/windows/Portable.ini"] = ""
config_files["FS-UAE/windows/Configurations/Default.fs-uae"] = """
[config]
amiga_model = A500
governor_warning = 0
"""
config_files["FS-UAE/linux/FS-UAE.AppImage.home/FS-UAE/Configurations/Default.fs-uae"] = """
[config]
amiga_model = A500
governor_warning = 0
"""

# FSUAE emulator
class FSUAE(base.EmulatorBase):

    # Get name
    def GetName(self):
        return "FS-UAE"

    # Get platforms
    def GetPlatforms(self):
        return config.fsuae_platforms

    # Get config
    def GetConfig(self):
        return {
            "FS-UAE": {
                "program": {
                    "windows": "FS-UAE/windows/Windows/x86-64/fs-uae.exe",
                    "linux": "FS-UAE/linux/FS-UAE.AppImage"
                },
                "save_dir": {
                    "windows": None,
                    "linux": None
                },
                "setup_dir": {
                    "windows": "FS-UAE/windows",
                    "linux": "FS-UAE/linux/FS-UAE.AppImage.home/FS-UAE"
                },
                "config_file": {
                    "windows": "FS-UAE/windows/Configurations/Default.fs-uae",
                    "linux": "FS-UAE/linux/FS-UAE.AppImage.home/FS-UAE/Configurations/Default.fs-uae"
                },
                "run_sandboxed": {
                    "windows": False,
                    "linux": False
                }
            }
        }

    # Download
    def Download(self, force_downloads = False):
        if force_downloads or programs.ShouldProgramBeInstalled("FS-UAE", "windows"):
            network.DownloadLatestGithubRelease(
                github_user = "FrodeSolheim",
                github_repo = "fs-uae",
                starts_with = "FS-UAE",
                ends_with = "Windows_x86-64.zip",
                search_file = "Plugin.ini",
                install_name = "FS-UAE",
                install_dir = programs.GetProgramInstallDir("FS-UAE", "windows"),
                get_latest = True,
                verbose = config.default_flag_verbose,
                exit_on_failure = config.default_flag_exit_on_failure)
        if force_downloads or programs.ShouldProgramBeInstalled("FS-UAE", "linux"):
            network.BuildAppImageFromSource(
                release_url = "https://github.com/FrodeSolheim/fs-uae/releases/download/v3.1.66/fs-uae-3.1.66.tar.xz",
                output_name = "FS-UAE",
                output_dir = programs.GetProgramInstallDir("FS-UAE", "linux"),
                build_cmd = [
                    "cd", "fs-uae-3.1.66",
                    "&&",
                    "./configure",
                    "&&",
                    "make", "-j", "8"
                ],
                internal_copies = [
                    {"from": "Source/fs-uae-3.1.66/fs-uae", "to": "AppImage/usr/bin/fs-uae"},
                    {"from": "Source/fs-uae-3.1.66/share/applications/fs-uae.desktop", "to": "AppImage/app.desktop"},
                    {"from": "Source/fs-uae-3.1.66/share/icons/hicolor/256x256/apps/fs-uae.png", "to": "AppImage/fs-uae.png"}
                ],
                internal_symlinks = [
                    {"from": "usr/bin/fs-uae", "to": "AppRun"}
                ],
                external_copies = [
                    {"from": "Source/fs-uae-3.1.66/fs-uae.dat", "to": "fs-uae.dat"}
                ],
                verbose = config.default_flag_verbose,
                exit_on_failure = config.default_flag_exit_on_failure)

    # Setup
    def Setup(self):
        system.CopyContents(
            src = environment.GetSyncedGameEmulatorSetupDir("FS-UAE"),
            dest = programs.GetEmulatorPathConfigValue("FS-UAE", "setup_dir", "linux"),
            skip_existing = True,
            verbose = config.default_flag_verbose,
            exit_on_failure = config.default_flag_exit_on_failure)
        system.CopyContents(
            src = environment.GetSyncedGameEmulatorSetupDir("FS-UAE"),
            dest = programs.GetEmulatorPathConfigValue("FS-UAE", "setup_dir", "windows"),
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
            programs.GetEmulatorProgram("FS-UAE"),
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
