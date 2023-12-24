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
config_files["VICE-C64/windows/sdl-vice.ini"] = ""
config_files["VICE-C64/linux/VICE-C64.AppImage.home/.config/vice/vicerc"] = ""

# ViceC64 emulator
class ViceC64(emulatorbase.EmulatorBase):

    # Get name
    def GetName(self):
        return "VICE-C64"

    # Get platforms
    def GetPlatforms(self):
        return [
            config.game_subcategory_commodore_64
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
    def Setup(self, verbose = False, exit_on_failure = False):

        # Download windows program
        if programs.ShouldProgramBeInstalled("VICE-C64", "windows"):
            network.DownloadLatestGithubRelease(
                github_user = "VICE-Team",
                github_repo = "svn-mirror",
                starts_with = "SDL2VICE",
                ends_with = "win64.zip",
                search_file = "x64sc.exe",
                install_name = "VICE-C64",
                install_dir = programs.GetProgramInstallDir("VICE-C64", "windows"),
                get_latest = True,
                verbose = verbose,
                exit_on_failure = exit_on_failure)

        # Download linux program
        if programs.ShouldProgramBeInstalled("VICE-C64", "linux"):
            network.BuildAppImageFromSource(
                release_url = "https://github.com/NearlyTRex/ViceC64.git",
                output_name = "VICE-C64",
                output_dir = programs.GetProgramInstallDir("VICE-C64", "linux"),
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
                exit_on_failure = exit_on_failure)

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
        game_info,
        capture_type,
        fullscreen = False,
        verbose = False,
        exit_on_failure = False):

        # Get launch command
        launch_cmd = [
            programs.GetEmulatorProgram("VICE-C64"),
            config.token_game_file
        ]

        # Launch game
        emulatorcommon.SimpleLaunch(
            game_info = game_info,
            launch_cmd = launch_cmd,
            capture_type = capture_type,
            verbose = verbose,
            exit_on_failure = exit_on_failure)
