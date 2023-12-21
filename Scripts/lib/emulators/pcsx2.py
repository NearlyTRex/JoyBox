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
import gui
import emulatorcommon
import emulatorbase

# Config files
config_files = {}
config_file_general = """
[UI]
SettingsVersion = 1

[Folders]
Bios = $EMULATOR_SETUP_ROOT/bios
Snapshots = $EMULATOR_SETUP_ROOT/snaps
SaveStates = $EMULATOR_SETUP_ROOT/sstates
MemoryCards = $GAME_SAVE_DIR
Logs = $EMULATOR_SETUP_ROOT/logs
Cheats = $EMULATOR_SETUP_ROOT/cheats
CheatsWS = $EMULATOR_SETUP_ROOT/cheats_ws
CheatsNI = $EMULATOR_SETUP_ROOT/cheats_ni
Cache = $EMULATOR_SETUP_ROOT/cache
Textures = $EMULATOR_SETUP_ROOT/textures
InputProfiles = $EMULATOR_SETUP_ROOT/inputprofiles

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

# PCSX2 emulator
class PCSX2(emulatorbase.EmulatorBase):

    # Get name
    def GetName(self):
        return "PCSX2"

    # Get platforms
    def GetPlatforms(self):
        return [
            config.game_subcategory_sony_playstation_2
        ]

    # Get config
    def GetConfig(self):
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
    def Download(self, force_downloads = False, verbose = False, exit_on_failure = False):
        if force_downloads or programs.ShouldProgramBeInstalled("PCSX2", "windows"):
            network.DownloadLatestGithubRelease(
                github_user = "PCSX2",
                github_repo = "pcsx2",
                starts_with = "pcsx2",
                ends_with = "windows-x64-Qt.7z",
                search_file = "pcsx2-qt.exe",
                install_name = "PCSX2",
                install_dir = programs.GetProgramInstallDir("PCSX2", "windows"),
                verbose = verbose,
                exit_on_failure = exit_on_failure)
        if force_downloads or programs.ShouldProgramBeInstalled("PCSX2", "linux"):
            network.DownloadLatestGithubRelease(
                github_user = "PCSX2",
                github_repo = "pcsx2",
                starts_with = "pcsx2",
                ends_with = ".AppImage",
                search_file = "PCSX2.AppImage",
                install_name = "PCSX2",
                install_dir = programs.GetProgramInstallDir("PCSX2", "linux"),
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
                src = environment.GetSyncedGameEmulatorSetupDir("PCSX2"),
                dest = programs.GetEmulatorPathConfigValue("PCSX2", "setup_dir", platform),
                skip_existing = True,
                verbose = verbose,
                exit_on_failure = exit_on_failure)

    # Launch
    def Launch(
        self,
        json_data,
        capture_type,
        fullscreen = False,
        verbose = False,
        exit_on_failure = False):

        # Get launch command
        launch_cmd = [
            programs.GetEmulatorProgram("PCSX2"),
            config.token_game_file
        ]
        if fullscreen:
            launch_cmd += [
                "-fullscreen"
            ]

        # Launch game
        emulatorcommon.SimpleLaunch(
            json_data = json_data,
            launch_cmd = launch_cmd,
            capture_type = capture_type,
            verbose = verbose,
            exit_on_failure = exit_on_failure)
