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
config_file_general = """
[ports.qt]
gb.bios=$EMULATOR_SETUP_ROOT/bios/gb_bios.bin
gbc.bios=$EMULATOR_SETUP_ROOT/bios/gbc_bios.bin
gba.bios=$EMULATOR_SETUP_ROOT/bios/gba_bios.bin
sgb.bios=$EMULATOR_SETUP_ROOT/bios/sgb_bios.bin
savegamePath=$GAME_SAVE_DIR
"""
config_files["mGBA/windows/portable.ini"] = ""
config_files["mGBA/windows/config.ini"] = config_file_general
config_files["mGBA/linux/mGBA.AppImage.home/.config/mgba/config.ini"] = config_file_general

# MGBA emulator
class MGBA(emulatorbase.EmulatorBase):

    # Get name
    def GetName(self):
        return "mGBA"

    # Get platforms
    def GetPlatforms(self):
        return [
            config.game_subcategory_nintendo_game_boy_advance,
            config.game_subcategory_nintendo_game_boy_advance_ereader,
            config.game_subcategory_nintendo_game_boy,
            config.game_subcategory_nintendo_game_boy_color,
            config.game_subcategory_nintendo_super_game_boy,
            config.game_subcategory_nintendo_super_game_boy_color
        ]

    # Get config
    def GetConfig(self):
        return {
            "mGBA": {
                "program": {
                    "windows": "mGBA/windows/mGBA.exe",
                    "linux": "mGBA/linux/mGBA.AppImage"
                },
                "save_dir": {
                    "windows": None,
                    "linux": None
                },
                "setup_dir": {
                    "windows": "mGBA/windows",
                    "linux": "mGBA/linux/mGBA.AppImage.home/.config/mgba"
                },
                "config_file": {
                    "windows": "mGBA/windows/config.ini",
                    "linux": "mGBA/linux/mGBA.AppImage.home/.config/mgba/config.ini"
                },
                "run_sandboxed": {
                    "windows": False,
                    "linux": False
                }
            }
        }

    # Download
    def Download(self, force_downloads = False, verbose = False, exit_on_failure = False):
        if force_downloads or programs.ShouldProgramBeInstalled("mGBA", "windows"):
            network.DownloadLatestGithubRelease(
                github_user = "mgba-emu",
                github_repo = "mgba",
                starts_with = "mGBA",
                ends_with = "win64.7z",
                search_file = "mGBA.exe",
                install_name = "mGBA",
                install_dir = programs.GetProgramInstallDir("mGBA", "windows"),
                get_latest = True,
                verbose = verbose,
                exit_on_failure = exit_on_failure)
        if force_downloads or programs.ShouldProgramBeInstalled("mGBA", "linux"):
            network.DownloadLatestGithubRelease(
                github_user = "mgba-emu",
                github_repo = "mgba",
                starts_with = "mGBA",
                ends_with = ".appimage",
                search_file = "mGBA.AppImage",
                install_name = "mGBA",
                install_dir = programs.GetProgramInstallDir("mGBA", "linux"),
                get_latest = True,
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

        # Copy setup files
        for platform in ["windows", "linux"]:
            system.CopyContents(
                src = environment.GetSyncedGameEmulatorSetupDir("mGBA"),
                dest = programs.GetEmulatorPathConfigValue("mGBA", "setup_dir", platform),
                skip_existing = True,
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
            programs.GetEmulatorProgram("mGBA"),
            config.token_game_file
        ]
        if fullscreen:
            launch_cmd += [
                "--fullscreen"
            ]

        # Launch game
        emulatorcommon.SimpleLaunch(
            json_data = json_data,
            launch_cmd = launch_cmd,
            capture_type = capture_type,
            verbose = verbose,
            exit_on_failure = exit_on_failure)
