# Imports
import os, os.path
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
config_file_general = """
[BIOS]
SearchDirectory = $EMULATOR_SETUP_ROOT/bios

[MemoryCards]
Card1Type = PerGameTitle
Card2Type = None
UsePlaylistTitle = true
Directory = $GAME_SAVE_DIR

[Folders]
Cache = $EMULATOR_SETUP_ROOT/cache
Cheats = $EMULATOR_SETUP_ROOT/cheats
Covers = $EMULATOR_SETUP_ROOT/covers
Dumps = $EMULATOR_SETUP_ROOT/dump
GameSettings = $EMULATOR_SETUP_ROOT/gamesettings
InputProfiles = $EMULATOR_SETUP_ROOT/inputprofiles
SaveStates = $EMULATOR_SETUP_ROOT/savestates
Screenshots = $EMULATOR_SETUP_ROOT/screenshots
Shaders = $EMULATOR_SETUP_ROOT/shaders
Textures = $EMULATOR_SETUP_ROOT/textures
"""
config_files["DuckStation/windows/portable.txt"] = ""
config_files["DuckStation/windows/settings.ini"] = config_file_general
config_files["DuckStation/linux/DuckStation.AppImage.home/.config/duckstation/settings.ini"] = config_file_general

# DuckStation emulator
class DuckStation(emulatorbase.EmulatorBase):

    # Get name
    def GetName(self):
        return "DuckStation"

    # Get platforms
    def GetPlatforms(self):
        return [
            config.game_subcategory_sony_playstation
        ]

    # Get config
    def GetConfig(self):
        return {
            "DuckStation": {
                "program": {
                    "windows": "DuckStation/windows/duckstation-qt-x64-ReleaseLTCG.exe",
                    "linux": "DuckStation/linux/DuckStation.AppImage"
                },
                "save_dir": {
                    "windows": "DuckStation/windows/memcards",
                    "linux": "DuckStation/linux/DuckStation.AppImage.home/.config/duckstation/memcards"
                },
                "setup_dir": {
                    "windows": "DuckStation/windows",
                    "linux": "DuckStation/linux/DuckStation.AppImage.home/.config/duckstation"
                },
                "config_file": {
                    "windows": "DuckStation/windows/settings.ini",
                    "linux": "DuckStation/linux/DuckStation.AppImage.home/.config/duckstation/settings.ini"
                },
                "run_sandboxed": {
                    "windows": False,
                    "linux": False
                }
            }
        }

    # Download
    def Download(self, force_downloads = False, verbose = False, exit_on_failure = False):
        if force_downloads or programs.ShouldProgramBeInstalled("DuckStation", "windows"):
            network.DownloadLatestGithubRelease(
                github_user = "stenzek",
                github_repo = "duckstation",
                starts_with = "duckstation",
                ends_with = "windows-x64-release.zip",
                search_file = "duckstation-qt-x64-ReleaseLTCG.exe",
                install_name = "DuckStation",
                install_dir = programs.GetProgramInstallDir("DuckStation", "windows"),
                get_latest = True,
                verbose = verbose,
                exit_on_failure = exit_on_failure)
        if force_downloads or programs.ShouldProgramBeInstalled("DuckStation", "linux"):
            network.DownloadLatestGithubRelease(
                github_user = "stenzek",
                github_repo = "duckstation",
                starts_with = "DuckStation",
                ends_with = ".AppImage",
                search_file = "DuckStation.AppImage",
                install_name = "DuckStation",
                install_dir = programs.GetProgramInstallDir("DuckStation", "linux"),
                get_latest = True,
                verbose = verbose,
                exit_on_failure = exit_on_failure)

    # Setup
    def Setup(self, verbose = False, exit_on_failure = False):

        # Create config files
        for config_filename, config_contents in config_files.items():
            system.TouchFile(
                src = os.path.join(environment.GetEmulatorsRootDir(), config_filename),
                contents = config_contents.strip(),
                verbose = verbose,
                exit_on_failure = exit_on_failure)

        # Copy setup files
        for platform in ["windows", "linux"]:
            system.CopyContents(
                src = environment.GetSyncedGameEmulatorSetupDir("DuckStation"),
                dest = programs.GetEmulatorPathConfigValue("DuckStation", "setup_dir", platform),
                skip_existing = True,
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
            programs.GetEmulatorProgram("DuckStation"),
            config.token_game_file
        ]
        if fullscreen:
            launch_cmd += [
                "-fullscreen"
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
