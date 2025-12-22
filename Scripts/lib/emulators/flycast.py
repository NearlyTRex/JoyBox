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
import gui
import emulatorcommon
import emulatorbase

# Config files
config_files = {}
config_files["Flycast/windows/emu.cfg"] = ""
config_files["Flycast/linux/Flycast.AppImage.home/.config/flycast/emu.cfg"] = ""

# System files
system_files = {}

# Flycast emulator
class Flycast(emulatorbase.EmulatorBase):

    # Get name
    def GetName(self):
        return "Flycast"

    # Get platforms
    def GetPlatforms(self):
        return [
            config.Platform.OTHER_SEGA_DREAMCAST
        ]

    # Get config
    def GetConfig(self):
        return {
            "Flycast": {
                "program": {
                    "windows": "Flycast/windows/flycast.exe",
                    "linux": "Flycast/linux/Flycast.AppImage"
                },
                "save_dir": {
                    "windows": "Flycast/windows/data",
                    "linux": "Flycast/linux/Flycast.AppImage.home/.local/share/flycast"
                },
                "config_file": {
                    "windows": "Flycast/windows/emu.cfg",
                    "linux": "Flycast/linux/Flycast.AppImage.home/.config/flycast/emu.cfg"
                },
                "run_sandboxed": {
                    "windows": False,
                    "linux": False
                }
            }
        }

    # Setup
    def Setup(self, setup_params = None):

        # Use default params if not provided
        if not setup_params:
            setup_params = config.SetupParams()

        # Download windows program
        if programs.ShouldProgramBeInstalled("Flycast", "windows"):
            success = release.DownloadGithubRelease(
                github_user = "flyinghead",
                github_repo = "flycast",
                starts_with = "flycast-win64",
                ends_with = ".zip",
                search_file = "flycast.exe",
                install_name = "Flycast",
                install_dir = programs.GetProgramInstallDir("Flycast", "windows"),
                backups_dir = programs.GetProgramBackupDir("Flycast", "windows"),
                get_latest = True,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup Flycast")
                return False

        # Build linux program
        if programs.ShouldProgramBeInstalled("Flycast", "linux"):
            success = release.BuildAppImageFromSource(
                release_url = "https://github.com/NearlyTRex/Flycast.git",
                output_file = "App-x86_64.AppImage",
                install_name = "Flycast",
                install_dir = programs.GetProgramInstallDir("Flycast", "linux"),
                backups_dir = programs.GetProgramBackupDir("Flycast", "linux"),
                build_cmd = [
                    "cmake", "..", "-DCMAKE_BUILD_TYPE=Release",
                    "&&",
                    "make", "-j", "4"
                ],
                build_dir = "Build",
                internal_copies = [
                    {"from": "Source/Build/flycast", "to": "AppImage/usr/bin/flycast"},
                    {"from": "AppImageTool/linux/app.desktop", "to": "AppImage/app.desktop"},
                    {"from": "AppImageTool/linux/icon.svg", "to": "AppImage/icon.svg"}
                ],
                internal_symlinks = [
                    {"from": "usr/bin/flycast", "to": "AppRun"}
                ],
                locker_type = setup_params.locker_type,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup Flycast")
                return False
        return True

    # Setup offline
    def SetupOffline(self, setup_params = None):

        # Use default params if not provided
        if not setup_params:
            setup_params = config.SetupParams()

        # Setup windows program
        if programs.ShouldProgramBeInstalled("Flycast", "windows"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetProgramBackupDir("Flycast", "windows"),
                install_name = "Flycast",
                install_dir = programs.GetProgramInstallDir("Flycast", "windows"),
                search_file = "flycast.exe",
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup Flycast")
                return False

        # Setup linux program
        if programs.ShouldProgramBeInstalled("Flycast", "linux"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetProgramBackupDir("Flycast", "linux"),
                install_name = "Flycast",
                install_dir = programs.GetProgramInstallDir("Flycast", "linux"),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup Flycast")
                return False
        return True

    # Configure
    def Configure(self, setup_params = None):

        # Use default params if not provided
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
                logger.log_error("Could not setup Flycast config files")
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
            programs.GetEmulatorProgram("Flycast"),
            config.token_game_file
        ]
        if fullscreen:
            launch_cmd += [
                "-config", "window:fullscreen=yes"
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
