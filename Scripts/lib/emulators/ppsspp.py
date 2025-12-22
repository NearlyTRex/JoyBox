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
            config.Platform.SONY_PLAYSTATION_NETWORK_PSP,
            config.Platform.SONY_PLAYSTATION_NETWORK_PSPM,
            config.Platform.SONY_PLAYSTATION_PORTABLE
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
    def Setup(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Download windows program
        if programs.ShouldProgramBeInstalled("PPSSPP", "windows"):
            success = release.DownloadWebpageRelease(
                webpage_url = "https://www.ppsspp.org/download",
                webpage_base_url = "https://www.ppsspp.org",
                starts_with = "https://www.ppsspp.org/files/",
                ends_with = "ppsspp_win.zip",
                search_file = "PPSSPPWindows64.exe",
                install_name = "PPSSPP",
                install_dir = programs.GetProgramInstallDir("PPSSPP", "windows"),
                backups_dir = programs.GetProgramBackupDir("PPSSPP", "windows"),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup PPSSPP")
                return False

        # Download linux program
        if programs.ShouldProgramBeInstalled("PPSSPP", "linux"):
            success = release.BuildAppImageFromSource(
                release_url = "https://github.com/NearlyTRex/PPSSPP.git",
                output_file = "PPSSPPSDL-x86_64.AppImage",
                install_name = "PPSSPP",
                install_dir = programs.GetProgramInstallDir("PPSSPP", "linux"),
                backups_dir = programs.GetProgramBackupDir("PPSSPP", "linux"),
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
                locker_type = setup_params.locker_type,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup PPSSPP")
                return False
        return True

    # Setup offline
    def SetupOffline(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Setup windows program
        if programs.ShouldProgramBeInstalled("PPSSPP", "windows"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetProgramBackupDir("PPSSPP", "windows"),
                install_name = "PPSSPP",
                install_dir = programs.GetProgramInstallDir("PPSSPP", "windows"),
                search_file = "PPSSPPWindows64.exe",
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup PPSSPP")
                return False

        # Setup linux program
        if programs.ShouldProgramBeInstalled("PPSSPP", "linux"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetProgramBackupDir("PPSSPP", "linux"),
                install_name = "PPSSPP",
                install_dir = programs.GetProgramInstallDir("PPSSPP", "linux"),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup PPSSPP")
                return False
        return True

    # Configure
    def Configure(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Create config files
        for config_filename, config_contents in config_files.items():
            success = fileops.touch_file(
                src = paths.join_paths(environment.GetEmulatorsRootDir(), config_filename),
                contents = config_contents.strip(),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup PPSSPP config files")
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
            programs.GetEmulatorProgram("PPSSPP"),
            config.token_game_file
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
