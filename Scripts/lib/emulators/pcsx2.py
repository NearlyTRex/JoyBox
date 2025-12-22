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
import hashing
import gui
import emulatorcommon
import emulatorbase

# Config files
config_files = {}
config_file_general = """
[UI]
SettingsVersion = 1

[Folders]
Bios = EMULATOR_SETUP_ROOT/bios
Snapshots = EMULATOR_SETUP_ROOT/snaps
SaveStates = EMULATOR_SETUP_ROOT/sstates
MemoryCards = GAME_SAVE_DIR
Logs = EMULATOR_SETUP_ROOT/logs
Cheats = EMULATOR_SETUP_ROOT/cheats
CheatsWS = EMULATOR_SETUP_ROOT/cheats_ws
CheatsNI = EMULATOR_SETUP_ROOT/cheats_ni
Cache = EMULATOR_SETUP_ROOT/cache
Textures = EMULATOR_SETUP_ROOT/textures
InputProfiles = EMULATOR_SETUP_ROOT/inputprofiles

[Filenames]
BIOS = ps2-0170a-20030325.bin

[MemoryCards]
Slot1_Enable = true
Slot1_Filename = Mcd001.ps2
Slot2_Enable = false
Slot2_Filename =
Multitap1_Slot2_Enable = false
Multitap1_Slot2_Filename = Mcd-Multitap1-Slot02.ps2
Multitap1_Slot3_Enable = false
Multitap1_Slot3_Filename = Mcd-Multitap1-Slot03.ps2
Multitap1_Slot4_Enable = false
Multitap1_Slot4_Filename = Mcd-Multitap1-Slot04.ps2
Multitap2_Slot2_Enable = false
Multitap2_Slot2_Filename = Mcd-Multitap2-Slot02.ps2
Multitap2_Slot3_Enable = false
Multitap2_Slot3_Filename = Mcd-Multitap2-Slot03.ps2
Multitap2_Slot4_Enable = false
Multitap2_Slot4_Filename = Mcd-Multitap2-Slot04.ps2

[EmuCore]
McdEnableEjection = true
McdFolderAutoManage = true

[Pad1]
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
L2 = SDL-0/+LeftTrigger
R1 = SDL-0/RightShoulder
R2 = SDL-0/+RightTrigger
L3 = SDL-0/LeftStick
R3 = SDL-0/RightStick
Analog = SDL-0/Guide
LUp = SDL-0/-LeftY
LRight = SDL-0/+LeftX
LDown = SDL-0/+LeftY
LLeft = SDL-0/-LeftX
RUp = SDL-0/-RightY
RRight = SDL-0/+RightX
RDown = SDL-0/+RightY
RLeft = SDL-0/-RightX
LargeMotor = SDL-0/LargeMotor
SmallMotor = SDL-0/SmallMotor
"""
config_files["PCSX2/windows/portable.ini"] = ""
config_files["PCSX2/windows/inis/PCSX2.ini"] = config_file_general
config_files["PCSX2/linux/PCSX2.AppImage.home/.config/PCSX2/inis/PCSX2.ini"] = config_file_general

# System files
system_files = {}
system_files["bios/ps2-0170e-20030227.bin"] = "6e69920fa6eef8522a1d688a11e41bc6"
system_files["bios/ps2-0170j-20030206.bin"] = "312ad4816c232a9606e56f946bc0678a"
system_files["bios/ps2-0170a-20030325.bin"] = "8aa12ce243210128c5074552d3b86251"

# PCSX2 emulator
class PCSX2(emulatorbase.EmulatorBase):

    # Get name
    def get_name(self):
        return "PCSX2"

    # Get platforms
    def get_platforms(self):
        return [
            config.Platform.SONY_PLAYSTATION_2
        ]

    # Get config
    def get_config(self):
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

    # Setup
    def setup(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Download windows program
        if programs.should_program_be_installed("PCSX2", "windows"):
            success = release.download_github_release(
                github_user = "PCSX2",
                github_repo = "pcsx2",
                starts_with = "pcsx2",
                ends_with = "windows-x64-Qt.7z",
                search_file = "pcsx2-qt.exe",
                install_name = "PCSX2",
                install_dir = programs.get_program_install_dir("PCSX2", "windows"),
                backups_dir = programs.get_program_backup_dir("PCSX2", "windows"),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup PCSX2")
                return False

        # Download linux program
        if programs.should_program_be_installed("PCSX2", "linux"):
            success = release.download_github_release(
                github_user = "PCSX2",
                github_repo = "pcsx2",
                starts_with = "pcsx2",
                ends_with = ".AppImage",
                install_name = "PCSX2",
                install_dir = programs.get_program_install_dir("PCSX2", "linux"),
                backups_dir = programs.get_program_backup_dir("PCSX2", "linux"),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup PCSX2")
                return False
        return True

    # Setup offline
    def setup_offline(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Setup windows program
        if programs.should_program_be_installed("PCSX2", "windows"):
            success = release.setup_stored_release(
                archive_dir = programs.get_program_backup_dir("PCSX2", "windows"),
                install_name = "PCSX2",
                install_dir = programs.get_program_install_dir("PCSX2", "windows"),
                search_file = "pcsx2-qt.exe",
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup PCSX2")
                return False

        # Setup linux program
        if programs.should_program_be_installed("PCSX2", "linux"):
            success = release.setup_stored_release(
                archive_dir = programs.get_program_backup_dir("PCSX2", "linux"),
                install_name = "PCSX2",
                install_dir = programs.get_program_install_dir("PCSX2", "linux"),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup PCSX2")
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
                logger.log_error("Could not setup PCSX2 config files")
                return False

        # Verify system files
        for filename, expected_md5 in system_files.items():
            actual_md5 = hashing.calculate_file_md5(
                src = paths.join_paths(environment.get_locker_gaming_emulator_setup_dir("PCSX2"), filename),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            success = (expected_md5 == actual_md5)
            if not success:
                logger.log_error("Could not verify PCSX2 system file %s" % filename)
                return False

        # Copy system files
        for filename in system_files.keys():
            for platform in ["windows", "linux"]:
                success = fileops.smart_copy(
                    src = paths.join_paths(environment.get_locker_gaming_emulator_setup_dir("PCSX2"), filename),
                    dest = paths.join_paths(programs.get_emulator_path_config_value("PCSX2", "setup_dir", platform), filename),
                    verbose = setup_params.verbose,
                    pretend_run = setup_params.pretend_run,
                    exit_on_failure = setup_params.exit_on_failure)
                if not success:
                    logger.log_error("Could not setup PCSX2 system files")
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
            programs.get_emulator_program("PCSX2"),
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
