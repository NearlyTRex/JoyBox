# Imports
import os, os.path
import sys

# Local imports
import config
import environment
import system
import logger
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
            config.Platform.OTHER_ATARI_JAGUAR,
            config.Platform.OTHER_ATARI_JAGUAR_CD
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
    def Setup(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Download windows program
        if programs.ShouldProgramBeInstalled("BigPEmu", "windows"):
            success = release.DownloadWebpageRelease(
                webpage_url = "https://www.richwhitehouse.com/jaguar/index.php?content=download",
                webpage_base_url = "https://www.richwhitehouse.com",
                starts_with = "https://www.richwhitehouse.com/jaguar/builds/BigPEmu",
                ends_with = ".zip",
                search_file = "BigPEmu.exe",
                install_name = "BigPEmu",
                install_dir = programs.GetProgramInstallDir("BigPEmu", "windows"),
                backups_dir = programs.GetProgramBackupDir("BigPEmu", "windows"),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup BigPEmu")
                return False
        return True

    # Setup offline
    def SetupOffline(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Setup windows program
        if programs.ShouldProgramBeInstalled("BigPEmu", "windows"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetProgramBackupDir("BigPEmu", "windows"),
                install_name = "BigPEmu",
                install_dir = programs.GetProgramInstallDir("BigPEmu", "windows"),
                search_file = "BigPEmu.exe",
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup BigPEmu")
                return False
        return True

    # Configure
    def Configure(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Create config files
        for config_filename, config_contents in config_files.items():
            success = system.TouchFile(
                src = system.JoinPaths(environment.GetEmulatorsRootDir(), config_filename),
                contents = config_contents.strip(),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup BigPEmu config files")
                return False
        return True

    # Launch
    def Launch(
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
            programs.GetEmulatorProgram("BigPEmu"),
            config.token_game_file,
            "-localdata"
        ]

        # Launch game
        return emulatorcommon.SimpleLaunch(
            game_info = game_info,
            launch_cmd = launch_cmd,
            capture_type = capture_type,
            capture_file = capture_file,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
