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
config_files["Atari800/windows/.atari800.cfg"] = ""
config_files["Atari800/linux/Atari800.AppImage.home/.atari800.cfg"] = ""

# Atari800 emulator
class Atari800(emulatorbase.EmulatorBase):

    # Get name
    def GetName(self):
        return "Atari800"

    # Get platforms
    def GetPlatforms(self):
        return [
            config.game_subcategory_atari_800
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

    # Download
    def Download(self, force_downloads = False, verbose = False, exit_on_failure = False):
        if force_downloads or programs.ShouldProgramBeInstalled("Atari800", "windows"):
            network.DownloadLatestGithubRelease(
                github_user = "atari800",
                github_repo = "atari800",
                starts_with = "atari800",
                ends_with = "win32-sdl.zip",
                search_file = "atari800.exe",
                install_name = "Atari800",
                install_dir = programs.GetProgramInstallDir("Atari800", "windows"),
                get_latest = True,
                verbose = verbose,
                exit_on_failure = exit_on_failure)
        if force_downloads or programs.ShouldProgramBeInstalled("Atari800", "linux"):
            network.BuildAppImageFromSource(
                release_url = "https://github.com/NearlyTRex/Atari800.git",
                output_name = "Atari800",
                output_dir = programs.GetProgramInstallDir("Atari800", "linux"),
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
            programs.GetEmulatorProgram("Atari800"),
            config.token_game_file
        ]

        # Launch game
        emulatorcommon.SimpleLaunch(
            launch_cmd = launch_cmd,
            launch_name = launch_name,
            launch_platform = launch_platform,
            launch_file = launch_file,
            launch_artwork = launch_artwork,
            launch_save_dir = launch_save_dir,
            launch_capture_type = launch_capture_type,
            verbose = verbose,
            exit_on_failure = exit_on_failure)
