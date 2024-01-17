# Imports
import os, os.path
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
config_files["BigPEmu/windows/placeholder.txt"] = ""

# System files
system_files = {}

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

    # Setup
    def Setup(self, verbose = False, exit_on_failure = False):

        # Download windows program
        if programs.ShouldProgramBeInstalled("BigPEmu", "windows"):
            success = release.DownloadWebpageRelease(
                webpage_url = "https://www.richwhitehouse.com/jaguar/index.php?content=download",
                starts_with = "https://www.richwhitehouse.com/jaguar/builds/BigPEmu",
                ends_with = ".zip",
                search_file = "BigPEmu.exe",
                install_name = "BigPEmu",
                install_dir = programs.GetProgramInstallDir("BigPEmu", "windows"),
                backups_dir = programs.GetProgramBackupDir("BigPEmu", "windows"),
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup BigPEmu")

        # Create config files
        for config_filename, config_contents in config_files.items():
            success = system.TouchFile(
                src = os.path.join(environment.GetEmulatorsRootDir(), config_filename),
                contents = config_contents.strip(),
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup BigPEmu config files")

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
            programs.GetEmulatorProgram("BigPEmu"),
            config.token_game_file,
            "-localdata"
        ]

        # Launch game
        emulatorcommon.SimpleLaunch(
            game_info = game_info,
            launch_cmd = launch_cmd,
            capture_type = capture_type,
            verbose = verbose,
            exit_on_failure = exit_on_failure)
