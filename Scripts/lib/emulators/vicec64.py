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
config_files["VICE-C64/windows/sdl-vice.ini"] = ""
config_files["VICE-C64/linux/VICE-C64.AppImage.home/.config/vice/vicerc"] = ""

# System files
system_files = {}

# ViceC64 emulator
class ViceC64(emulatorbase.EmulatorBase):

    # Get name
    def GetName(self):
        return "VICE-C64"

    # Get platforms
    def GetPlatforms(self):
        return [
            config.Platform.OTHER_COMMODORE_64
        ]

    # Get config
    def GetConfig(self):
        return {
            "VICE-C64": {
                "program": {
                    "windows": "VICE-C64/windows/x64sc.exe",
                    "linux": "VICE-C64/linux/VICE-C64.AppImage"
                },
                "save_dir": {
                    "windows": None,
                    "linux": None
                },
                "config_file": {
                    "windows": "VICE-C64/windows/sdl-vice.ini",
                    "linux": "VICE-C64/linux/VICE-C64.AppImage.home/.config/vice/vicerc"
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
        if programs.ShouldProgramBeInstalled("VICE-C64", "windows"):
            success = release.DownloadGithubRelease(
                github_user = "VICE-Team",
                github_repo = "svn-mirror",
                starts_with = "SDL2VICE",
                ends_with = "win64.zip",
                search_file = "x64sc.exe",
                install_name = "VICE-C64",
                install_dir = programs.GetProgramInstallDir("VICE-C64", "windows"),
                backups_dir = programs.GetProgramBackupDir("VICE-C64", "windows"),
                get_latest = True,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                system.LogError("Could not setup VICE-C64")
                return False

        # Download linux program
        if programs.ShouldProgramBeInstalled("VICE-C64", "linux"):
            success = release.BuildAppImageFromSource(
                release_url = "https://github.com/NearlyTRex/ViceC64.git",
                output_file = "App-x86_64.AppImage",
                install_name = "VICE-C64",
                install_dir = programs.GetProgramInstallDir("VICE-C64", "linux"),
                backups_dir = programs.GetProgramBackupDir("VICE-C64", "linux"),
                build_cmd = [
                    "cd", "vice",
                    "&&",
                    "./autogen.sh",
                    "&&",
                    "./configure", "--disable-html-docs", "--enable-pdf-docs=no",
                    "&&",
                    "make", "-j", "4"
                ],
                internal_copies = [
                    {"from": "Source/vice/data", "to": "AppImage/usr/bin"},
                    {"from": "Source/vice/src/x64sc", "to": "AppImage/usr/bin/x64sc"},
                    {"from": "AppImageTool/linux/app.desktop", "to": "AppImage/app.desktop"},
                    {"from": "AppImageTool/linux/icon.svg", "to": "AppImage/icon.svg"}
                ],
                internal_symlinks = [
                    {"from": "usr/bin/x64sc", "to": "AppRun"}
                ],
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                system.LogError("Could not setup VICE-C64")
                return False
        return True

    # Setup offline
    def SetupOffline(self, verbose = False, pretend_run = False, exit_on_failure = False):

        # Setup windows program
        if programs.ShouldProgramBeInstalled("VICE-C64", "windows"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetProgramBackupDir("VICE-C64", "windows"),
                install_name = "VICE-C64",
                install_dir = programs.GetProgramInstallDir("VICE-C64", "windows"),
                search_file = "x64sc.exe",
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                system.LogError("Could not setup REPLACEME")
                return False

        # Setup linux program
        if programs.ShouldProgramBeInstalled("VICE-C64", "linux"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetProgramBackupDir("VICE-C64", "linux"),
                install_name = "VICE-C64",
                install_dir = programs.GetProgramInstallDir("VICE-C64", "linux"),
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                system.LogError("Could not setup VICE-C64")
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
                system.LogError("Could not setup VICE-C64 config files")
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
            programs.GetEmulatorProgram("VICE-C64"),
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
