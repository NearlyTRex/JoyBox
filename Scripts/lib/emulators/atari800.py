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
config_files["Atari800/windows/.atari800.cfg"] = ""
config_files["Atari800/linux/Atari800.AppImage.home/.atari800.cfg"] = ""

# System files
system_files = {}

# Atari800 emulator
class Atari800(emulatorbase.EmulatorBase):

    # Get name
    def GetName(self):
        return "Atari800"

    # Get platforms
    def GetPlatforms(self):
        return [
            config.Platform.OTHER_ATARI_800
        ]

    # Get config
    def GetConfig(self):
        return {
            "Atari800": {
                "program": {
                    "windows": "Atari800/windows/atari800.exe",
                    "linux": "Atari800/linux/Atari800.AppImage"
                },
                "save_dir": {
                    "windows": None,
                    "linux": None
                },
                "config_file": {
                    "windows": "Atari800/windows/.atari800.cfg",
                    "linux": "Atari800/linux/Atari800.AppImage.home/.atari800.cfg"
                },
                "run_sandboxed": {
                    "windows": False,
                    "linux": False
                }
            }
        }

    # Setup
    def Setup(self, verbose = False, pretend_run = False, exit_on_failure = False):

        # Download windows program
        if programs.ShouldProgramBeInstalled("Atari800", "windows"):
            success = release.DownloadGithubRelease(
                github_user = "atari800",
                github_repo = "atari800",
                starts_with = "atari800",
                ends_with = "win32-sdl.zip",
                search_file = "atari800.exe",
                install_name = "Atari800",
                install_dir = programs.GetProgramInstallDir("Atari800", "windows"),
                backups_dir = programs.GetProgramBackupDir("Atari800", "windows"),
                get_latest = True,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                system.LogError("Could not setup Atari800")
                return False

        # Build linux program
        if programs.ShouldProgramBeInstalled("Atari800", "linux"):
            success = release.BuildAppImageFromSource(
                release_url = "https://github.com/NearlyTRex/Atari800.git",
                output_file = "Atari800-x86_64.AppImage",
                install_name = "Atari800",
                install_dir = programs.GetProgramInstallDir("Atari800", "linux"),
                backups_dir = programs.GetProgramBackupDir("Atari800", "linux"),
                build_cmd = [
                    "./autogen.sh",
                    "&&",
                    "./configure",
                    "&&",
                    "make", "-j", "4"
                ],
                internal_copies = [
                    {"from": "Source/act", "to": "AppImage/usr/bin"},
                    {"from": "Source/src/atari800", "to": "AppImage/usr/bin/atari800"},
                    {"from": "Source/debian/atari800.desktop", "to": "AppImage/atari800.desktop"},
                    {"from": "Source/data/atari1.png", "to": "AppImage/atari800.png"}
                ],
                internal_symlinks = [
                    {"from": "usr/bin/atari800", "to": "AppRun"}
                ],
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                system.LogError("Could not setup Atari800")
                return False
        return True

    # Setup offline
    def SetupOffline(self, verbose = False, pretend_run = False, exit_on_failure = False):

        # Setup windows program
        if programs.ShouldProgramBeInstalled("Atari800", "windows"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetProgramBackupDir("Atari800", "windows"),
                install_name = "Atari800",
                install_dir = programs.GetProgramInstallDir("Atari800", "windows"),
                search_file = "atari800.exe",
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                system.LogError("Could not setup Atari800")
                return False

        # Setup linux program
        if programs.ShouldProgramBeInstalled("Atari800", "linux"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetProgramBackupDir("Atari800", "linux"),
                install_name = "Atari800",
                install_dir = programs.GetProgramInstallDir("Atari800", "linux"),
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                system.LogError("Could not setup Atari800")
                return False
        return True

    # Configure
    def Configure(self, verbose = False, pretend_run = False, exit_on_failure = False):

        # Create config files
        for config_filename, config_contents in config_files.items():
            success = system.TouchFile(
                src = system.JoinPaths(environment.GetEmulatorsRootDir(), config_filename),
                contents = config_contents.strip(),
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                system.LogError("Could not setup Atari800 config files")
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
            programs.GetEmulatorProgram("Atari800"),
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
