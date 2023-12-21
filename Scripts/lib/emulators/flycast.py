# Imports
import os, os.path
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
config_files["Flycast/windows/emu.cfg"] = ""
config_files["Flycast/linux/Flycast.AppImage.home/.config/flycast/emu.cfg"] = ""

# Flycast emulator
class Flycast(emulatorbase.EmulatorBase):

    # Get name
    def GetName(self):
        return "Flycast"

    # Get platforms
    def GetPlatforms(self):
        return [
            config.game_subcategory_sega_dreamcast
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

    # Download
    def Download(self, force_downloads = False, verbose = False, exit_on_failure = False):
        if force_downloads or programs.ShouldProgramBeInstalled("Flycast", "windows"):
            network.DownloadLatestGithubRelease(
                github_user = "flyinghead",
                github_repo = "flycast",
                starts_with = "flycast-win64",
                ends_with = ".zip",
                search_file = "flycast.exe",
                install_name = "Flycast",
                install_dir = programs.GetProgramInstallDir("Flycast", "windows"),
                get_latest = True,
                verbose = verbose,
                exit_on_failure = exit_on_failure)
        if force_downloads or programs.ShouldProgramBeInstalled("Flycast", "linux"):
            network.BuildAppImageFromSource(
                release_url = "https://github.com/NearlyTRex/Flycast.git",
                output_name = "Flycast",
                output_dir = programs.GetProgramInstallDir("Flycast", "linux"),
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
        json_data,
        capture_type,
        fullscreen = False,
        verbose = False,
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
        emulatorcommon.SimpleLaunch(
            json_data = json_data,
            launch_cmd = launch_cmd,
            capture_type = capture_type,
            verbose = verbose,
            exit_on_failure = exit_on_failure)
