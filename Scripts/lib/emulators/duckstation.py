# Imports
import os, os.path
import sys

# Local imports
import config
import environment
import system
import network
import programs
import gui
import emulatorcommon
import emulatorbase

# Config files
config_files = {}
config_file_general = """
[Main]
SettingsVersion = 3

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

[ControllerPorts]
ControllerSettingsMigrated = true

[InputSources]
SDL = true

[Pad1]
Type = AnalogController
Up = SDL-0/DPadUp
Right = SDL-0/DPadRight
Down = SDL-0/DPadDown
Left = SDL-0/DPadLeft
Triangle = SDL-0/Y
Circle = SDL-0/B
Cross = SDL-0/A
Square = SDL-0/X
Select = SDL-0/Back
Start = SDL-0/Start
L1 = SDL-0/LeftShoulder
R1 = SDL-0/RightShoulder
L2 = SDL-0/+LeftTrigger
R2 = SDL-0/+RightTrigger
L3 = SDL-0/LeftStick
R3 = SDL-0/RightStick
LLeft = SDL-0/-LeftX
LRight = SDL-0/+LeftX
LDown = SDL-0/+LeftY
LUp = SDL-0/-LeftY
RLeft = SDL-0/-RightX
RRight = SDL-0/+RightX
RDown = SDL-0/+RightY
RUp = SDL-0/-RightY
Analog = SDL-0/Guide
SmallMotor = SDL-0/SmallMotor
LargeMotor = SDL-0/LargeMotor
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
        game_info,
        capture_type,
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
        emulatorcommon.SimpleLaunch(
            game_info = game_info,
            launch_cmd = launch_cmd,
            capture_type = capture_type,
            verbose = verbose,
            exit_on_failure = exit_on_failure)
