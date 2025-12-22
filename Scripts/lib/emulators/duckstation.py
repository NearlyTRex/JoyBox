# Imports
import os, os.path
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
import hashing
import gui
import emulatorcommon
import emulatorbase

# Config files
config_files = {}
config_file_general = """
[Main]
SettingsVersion = 3

[BIOS]
SearchDirectory = EMULATOR_SETUP_ROOT/bios

[MemoryCards]
Card1Type = PerGameTitle
Card2Type = None
UsePlaylistTitle = true
Directory = GAME_SAVE_DIR

[Folders]
Cache = EMULATOR_SETUP_ROOT/cache
Cheats = EMULATOR_SETUP_ROOT/cheats
Covers = EMULATOR_SETUP_ROOT/covers
Dumps = EMULATOR_SETUP_ROOT/dump
GameSettings = EMULATOR_SETUP_ROOT/gamesettings
InputProfiles = EMULATOR_SETUP_ROOT/inputprofiles
SaveStates = EMULATOR_SETUP_ROOT/savestates
Screenshots = EMULATOR_SETUP_ROOT/screenshots
Shaders = EMULATOR_SETUP_ROOT/shaders
Textures = EMULATOR_SETUP_ROOT/textures

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

# System files
system_files = {}
system_files["bios/scph5500.bin"] = "8dd7d5296a650fac7319bce665a6a53c"
system_files["bios/scph7001.bin"] = "1e68c231d0896b7eadcad1d7d8e76129"
system_files["bios/scph1001.bin"] = "924e392ed05558ffdb115408c263dccf"
system_files["bios/scph5501.bin"] = "490f666e1afb15b7362b406ed1cea246"
system_files["bios/scph5502.bin"] = "32736f17079d0b2b7024407c39bd3050"
system_files["bios/scph7502.bin"] = "b9d9a0286c33dc6b7237bb13cd46fdee"

# DuckStation emulator
class DuckStation(emulatorbase.EmulatorBase):

    # Get name
    def get_name(self):
        return "DuckStation"

    # Get platforms
    def get_platforms(self):
        return [
            config.Platform.SONY_PLAYSTATION
        ]

    # Get config
    def get_config(self):
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

    # Setup
    def setup(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Download windows program
        if programs.should_program_be_installed("DuckStation", "windows"):
            success = release.download_github_release(
                github_user = "stenzek",
                github_repo = "duckstation",
                starts_with = "duckstation",
                ends_with = "windows-x64-release.zip",
                search_file = "duckstation-qt-x64-ReleaseLTCG.exe",
                install_name = "DuckStation",
                install_dir = programs.get_program_install_dir("DuckStation", "windows"),
                backups_dir = programs.get_program_backup_dir("DuckStation", "windows"),
                get_latest = True,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup DuckStation")
                return False

        # Download linux program
        if programs.should_program_be_installed("DuckStation", "linux"):
            success = release.download_github_release(
                github_user = "stenzek",
                github_repo = "duckstation",
                starts_with = "DuckStation",
                ends_with = ".AppImage",
                install_name = "DuckStation",
                install_dir = programs.get_program_install_dir("DuckStation", "linux"),
                backups_dir = programs.get_program_backup_dir("DuckStation", "linux"),
                get_latest = True,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup DuckStation")
                return False
        return True

    # Setup offline
    def setup_offline(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Setup windows program
        if programs.should_program_be_installed("DuckStation", "windows"):
            success = release.setup_stored_release(
                archive_dir = programs.get_program_backup_dir("DuckStation", "windows"),
                install_name = "DuckStation",
                install_dir = programs.get_program_install_dir("DuckStation", "windows"),
                search_file = "duckstation-qt-x64-ReleaseLTCG.exe",
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup DuckStation")
                return False

        # Setup linux program
        if programs.should_program_be_installed("DuckStation", "linux"):
            success = release.setup_stored_release(
                archive_dir = programs.get_program_backup_dir("DuckStation", "linux"),
                install_name = "DuckStation",
                install_dir = programs.get_program_install_dir("DuckStation", "linux"),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup DuckStation")
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
                logger.log_error("Could not setup DuckStation config files")
                return False

        # Verify system files
        for filename, expected_md5 in system_files.items():
            actual_md5 = hashing.calculate_file_md5(
                src = paths.join_paths(environment.get_locker_gaming_emulator_setup_dir("DuckStation"), filename),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            success = (expected_md5 == actual_md5)
            if not success:
                logger.log_error("Could not verify DuckStation system file %s" % filename)
                return False

        # Copy system files
        for filename in system_files.keys():
            for platform in ["windows", "linux"]:
                success = fileops.smart_copy(
                    src = paths.join_paths(environment.get_locker_gaming_emulator_setup_dir("DuckStation"), filename),
                    dest = paths.join_paths(programs.get_emulator_path_config_value("DuckStation", "setup_dir", platform), filename),
                    verbose = setup_params.verbose,
                    pretend_run = setup_params.pretend_run,
                    exit_on_failure = setup_params.exit_on_failure)
                if not success:
                    logger.log_error("Could not setup DuckStation system files")
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
            programs.get_emulator_program("DuckStation"),
            config.token_game_file
        ]
        if fullscreen:
            launch_cmd += [
                "-fullscreen"
            ]

        # Launch game
        return emulatorcommon.simple_launch(
            game_info = game_info,
            launch_cmd = launch_cmd,
            capture_type = capture_type,
            capture_file = capture_file,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
