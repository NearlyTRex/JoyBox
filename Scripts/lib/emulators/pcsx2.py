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
import launchcommon
import gui
import emulatorbase

# Config files
config_files = {}
config_files["PCSX2/windows/portable.ini"] = ""
config_files["PCSX2/windows/inis/PCSX2.ini"] = """
[Folders]
Bios = $EMULATOR_MAIN_ROOT/PCSX2/windows/bios
Snapshots = $EMULATOR_MAIN_ROOT/PCSX2/windows/snaps
SaveStates = $EMULATOR_MAIN_ROOT/PCSX2/windows/sstates
MemoryCards = $GAME_SAVE_DIR
Logs = $EMULATOR_MAIN_ROOT/PCSX2/windows/logs
Cheats = $EMULATOR_MAIN_ROOT/PCSX2/windows/cheats
CheatsWS = $EMULATOR_MAIN_ROOT/PCSX2/windows/cheats_ws
CheatsNI = $EMULATOR_MAIN_ROOT/PCSX2/windows/cheats_ni
Cache = $EMULATOR_MAIN_ROOT/PCSX2/windows/cache
Textures = $EMULATOR_MAIN_ROOT/PCSX2/windows/textures
InputProfiles = $EMULATOR_MAIN_ROOT/PCSX2/windows/inputprofiles

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
"""
config_files["PCSX2/linux/PCSX2.AppImage.home/.config/PCSX2/inis/PCSX2.ini"] = """
[Folders]
Bios = $EMULATOR_MAIN_ROOT/PCSX2/linux/PCSX2.AppImage.home/.config/PCSX2/bios
Snapshots = $EMULATOR_MAIN_ROOT/PCSX2/linux/PCSX2.AppImage.home/.config/PCSX2/snaps
SaveStates = $EMULATOR_MAIN_ROOT/PCSX2/linux/PCSX2.AppImage.home/.config/PCSX2/sstates
MemoryCards = $GAME_SAVE_DIR
Logs = $EMULATOR_MAIN_ROOT/PCSX2/linux/PCSX2.AppImage.home/.config/PCSX2/logs
Cheats = $EMULATOR_MAIN_ROOT/PCSX2/linux/PCSX2.AppImage.home/.config/PCSX2/cheats
CheatsWS = $EMULATOR_MAIN_ROOT/PCSX2/linux/PCSX2.AppImage.home/.config/PCSX2/cheats_ws
CheatsNI = $EMULATOR_MAIN_ROOT/PCSX2/linux/PCSX2.AppImage.home/.config/PCSX2/cheats_ni
Cache = $EMULATOR_MAIN_ROOT/PCSX2/linux/PCSX2.AppImage.home/.config/PCSX2/cache
Textures = $EMULATOR_MAIN_ROOT/PCSX2/linux/PCSX2.AppImage.home/.config/PCSX2/textures
InputProfiles = $EMULATOR_MAIN_ROOT/PCSX2/linux/PCSX2.AppImage.home/.config/PCSX2/inputprofiles

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
"""

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
                contents = config_contents,
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
            programs.GetEmulatorProgram("PCSX2"),
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
