# Imports
import os
import os.path
import sys

# Local imports
import config
import environment
import system
import release
import programs
import gui
import emulatorcommon
import emulatorbase

# Config files
config_files = {}
config_files["PPSSPP/windows/memstick/PSP/SYSTEM/ppsspp.ini"] = ""
config_files["PPSSPP/linux/PPSSPP.AppImage.home/.config/ppsspp/PSP/SYSTEM/ppsspp.ini"] = ""

# System files
system_files = {}

# PPSSPP emulator
class PPSSPP(emulatorbase.EmulatorBase):

    # Get name
    def GetName(self):
        return "PPSSPP"

    # Get platforms
    def GetPlatforms(self):
        return [
            config.game_subcategory_sony_playstation_network_psp,
            config.game_subcategory_sony_playstation_network_pspm,
            config.game_subcategory_sony_playstation_portable
        ]

    # Get config
    def GetConfig(self):
        return {
            "PPSSPP": {
                "program": {
                    "windows": "PPSSPP/windows/PPSSPPWindows64.exe",
                    "linux": "PPSSPP/linux/PPSSPP.AppImage"
                },
                "save_dir": {
                    "windows": "PPSSPP/windows/memstick/PSP/SAVEDATA",
                    "linux": "PPSSPP/linux/PPSSPP.AppImage.home/.config/ppsspp/PSP/SAVEDATA"
                },
                "config_file": {
                    "windows": "PPSSPP/windows/memstick/PSP/SYSTEM/ppsspp.ini",
                    "linux": "PPSSPP/linux/PPSSPP.AppImage.home/.config/ppsspp/PSP/SYSTEM/ppsspp.ini"
                },
                "run_sandboxed": {
                    "windows": False,
                    "linux": False
                }
            }
        }

    # Setup
    def Setup(self, verbose = False, exit_on_failure = False):

        # Download windows program
        if programs.ShouldProgramBeInstalled("PPSSPP", "windows"):
            success = release.DownloadWebpageRelease(
                webpage_url = "https://www.ppsspp.org/download/",
                starts_with = "https://www.ppsspp.org/files/",
                ends_with = "ppsspp_win.zip",
                search_file = "PPSSPPWindows64.exe",
                install_name = "PPSSPP",
                install_dir = programs.GetProgramInstallDir("PPSSPP", "windows"),
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup PPSSPP")

        # Download linux program
        if programs.ShouldProgramBeInstalled("PPSSPP", "linux"):
            success = release.BuildAppImageFromSource(
                release_url = "https://github.com/NearlyTRex/PPSSPP.git",
                output_name = "PPSSPP",
                output_dir = programs.GetProgramInstallDir("PPSSPP", "linux"),
                build_cmd = [
                    "cmake", "..", "-DLINUX_LOCAL_DEV=true", "-DCMAKE_BUILD_TYPE=Release",
                    "&&",
                    "make", "-j", "4"
                ],
                build_dir = "Build",
                internal_copies = [
                    {"from": "Source/Build/PPSSPPSDL", "to": "AppImage/usr/bin/PPSSPPSDL"},
                    {"from": "Source/Build/assets", "to": "AppImage/usr/bin/assets"},
                    {"from": "Source/Build/ppsspp.desktop", "to": "AppImage/ppsspp.desktop"},
                    {"from": "Source/icons/icon-512.svg", "to": "AppImage/ppsspp.svg"}
                ],
                internal_symlinks = [
                    {"from": "usr/bin/PPSSPPSDL", "to": "AppRun"}
                ],
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup PPSSPP")

        # Create config files
        for config_filename, config_contents in config_files.items():
            success = system.TouchFile(
                src = os.path.join(environment.GetEmulatorsRootDir(), config_filename),
                contents = config_contents.strip(),
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup PPSSPP config files")

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
            programs.GetEmulatorProgram("PPSSPP"),
            config.token_game_file
        ]

        # Launch game
        emulatorcommon.SimpleLaunch(
            game_info = game_info,
            launch_cmd = launch_cmd,
            capture_type = capture_type,
            verbose = verbose,
            exit_on_failure = exit_on_failure)
