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
config_files["BigPEmu/windows/placeholder.txt"] = ""

# BigPEmu emulator
class BigPEmu(emulatorbase.EmulatorBase):

    # Get name
    def GetName(self):
        return "BigPEmu"

    # Get platforms
    def GetPlatforms(self):
        return [
            config.game_subcategory_atari_jaguar,
            config.game_subcategory_atari_jaguar_cd
        ]

    # Get config
    def GetConfig(self):
        return {
            "BigPEmu": {
                "program": {
                    "windows": "BigPEmu/windows/BigPEmu.exe",
                    "linux": "BigPEmu/windows/BigPEmu.exe"
                },
                "save_dir": {
                    "windows": "BigPEmu/windows/UserData",
                    "linux": "BigPEmu/windows/UserData"
                },
                "config_file": {
                    "windows": None,
                    "linux": None
                },
                "run_sandboxed": {
                    "windows": False,
                    "linux": True
                }
            }
        }

    # Download
    def Download(self, force_downloads = False, verbose = False, exit_on_failure = False):
        if force_downloads or programs.ShouldProgramBeInstalled("BigPEmu", "windows"):
            network.DownloadGeneralRelease(
                archive_url = "https://www.richwhitehouse.com/jaguar/builds/BigPEmu_v1092.zip",
                search_file = "BigPEmu.exe",
                install_name = "BigPEmu",
                install_dir = programs.GetProgramInstallDir("BigPEmu", "windows"),
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
            programs.GetEmulatorProgram("BigPEmu"),
            config.token_game_file,
            "-localdata"
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
