# Imports
import os, os.path
import sys

# Local imports
import config
import environment
import system
import network
import programs
import archive
import nintendo
import gui
import emulatorcommon
import emulatorbase

# Config files
config_files = {}
config_file_general = """
[Data%20Storage]
nand_directory=$EMULATOR_SETUP_ROOT/nand/
sdmc_directory=$EMULATOR_SETUP_ROOT/sdmc/

[UI]
Paths\screenshotPath=$EMULATOR_SETUP_ROOT/screenshots/
"""
config_files["Citra/windows/user/config/qt-config.ini"] = config_file_general
config_files["Citra/linux/citra-qt.AppImage.home/.config/citra-emu/qt-config.ini"] = config_file_general

# System files
system_files = {}
system_files["nand.zip"] = "7c9baaa35b620bbd2b18b4620e2831e1"
system_files["sysdata.zip"] = "dcfa1fbaf7845c735b2c7d1ec9df2ed7"

# Citra emulator
class Citra(emulatorbase.EmulatorBase):

    # Get name
    def GetName(self):
        return "Citra"

    # Get platforms
    def GetPlatforms(self):
        return [
            config.game_subcategory_nintendo_3ds,
            config.game_subcategory_nintendo_3ds_apps,
            config.game_subcategory_nintendo_3ds_eshop
        ]

    # Get config
    def GetConfig(self):
        return {
            "Citra": {
                "program": {
                    "windows": "Citra/windows/citra-qt.exe",
                    "linux": "Citra/linux/citra-qt.AppImage"
                },
                "save_dir": {
                    "windows": "Citra/windows/user/sdmc/Nintendo 3DS/00000000000000000000000000000000/00000000000000000000000000000000/title/00040000",
                    "linux": "Citra/linux/citra-qt.AppImage.home/.local/share/citra-emu/sdmc/Nintendo 3DS/00000000000000000000000000000000/00000000000000000000000000000000/title/00040000"
                },
                "setup_dir": {
                    "windows": "Citra/windows/user",
                    "linux": "Citra/linux/citra-qt.AppImage.home/.local/share/citra-emu"
                },
                "config_file": {
                    "windows": "Citra/windows/user/config/qt-config.ini",
                    "linux": "Citra/linux/citra-qt.AppImage.home/.config/citra-emu/qt-config.ini"
                },
                "run_sandboxed": {
                    "windows": False,
                    "linux": False
                }
            }
        }

    # Install add-ons
    def InstallAddons(self, dlc_dirs = [], update_dirs = [], verbose = False, exit_on_failure = False):
        for package_dirset in [dlc_dirs, update_dirs]:
            for package_dir in package_dirset:
                for cia_file in system.BuildFileListByExtensions(package_dir, extensions = [".cia"]):
                    success = nintendo.Install3DSCIA(
                        src_3ds_file = cia_file,
                        sdmc_dir = os.path.join(programs.GetEmulatorPathConfigValue("Citra", "setup_dir"), "sdmc"),
                        verbose = verbose,
                        exit_on_failure = exit_on_failure)
                    if not success:
                        return False
        return True

    # Setup
    def Setup(self, verbose = False, exit_on_failure = False):

        # Download windows program
        if programs.ShouldProgramBeInstalled("Citra", "windows"):
            success = network.DownloadLatestGithubRelease(
                github_user = "citra-emu",
                github_repo = "citra-nightly",
                starts_with = "citra-windows-msvc",
                ends_with = ".7z",
                search_file = "citra-qt.exe",
                install_name = "Citra",
                install_dir = programs.GetProgramInstallDir("Citra", "windows"),
                get_latest = True,
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup Citra")

        # Download linux program
        if programs.ShouldProgramBeInstalled("Citra", "linux"):
            success = network.DownloadLatestGithubRelease(
                github_user = "citra-emu",
                github_repo = "citra-nightly",
                starts_with = "citra-linux-appimage",
                ends_with = ".tar.gz",
                search_file = "citra-qt.AppImage",
                install_name = "Citra",
                install_dir = programs.GetProgramInstallDir("Citra", "linux"),
                get_latest = True,
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup Citra")

        # Create config files
        for config_filename, config_contents in config_files.items():
            success = system.TouchFile(
                src = os.path.join(environment.GetEmulatorsRootDir(), config_filename),
                contents = config_contents.strip(),
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup Citra config files")

        # Extract setup files
        for platform in ["windows", "linux"]:
            for obj in ["nand", "sysdata"]:
                if os.path.exists(os.path.join(environment.GetSyncedGameEmulatorSetupDir("Citra"), obj + ".zip")):
                    success = archive.ExtractArchive(
                        archive_file = os.path.join(environment.GetSyncedGameEmulatorSetupDir("Citra"), obj + ".zip"),
                        extract_dir = os.path.join(programs.GetEmulatorPathConfigValue("Citra", "setup_dir", platform), obj),
                        skip_existing = True,
                        verbose = verbose,
                        exit_on_failure = exit_on_failure)
                    system.AssertCondition(success, "Could not setup Citra system files")

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
            programs.GetEmulatorProgram("Citra"),
            config.token_game_file
        ]

        # Launch game
        emulatorcommon.SimpleLaunch(
            game_info = game_info,
            launch_cmd = launch_cmd,
            capture_type = capture_type,
            verbose = verbose,
            exit_on_failure = exit_on_failure)
