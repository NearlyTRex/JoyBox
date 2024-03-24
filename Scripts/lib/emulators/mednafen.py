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
import hashing
import gui
import emulatorcommon
import emulatorbase

# Config files
config_files = {}
config_files["Mednafen/windows/mednafen.cfg"] = ""
config_files["Mednafen/linux/Mednafen.AppImage.home/.mednafen/mednafen.cfg"] = ""

# System files
system_files = {}
system_files["firmware/lynxboot.img"] = "fcd403db69f54290b51035d82f835e7b"

# Mednafen emulator
class Mednafen(emulatorbase.EmulatorBase):

    # Get name
    def GetName(self):
        return "Mednafen"

    # Get platforms
    def GetPlatforms(self):
        return [

            # Nintendo
            config.game_subcategory_nintendo_virtual_boy,

            # Other
            config.game_subcategory_atari_lynx
        ]

    # Get config
    def GetConfig(self):
        return {
            "Mednafen": {
                "program": {
                    "windows": "Mednafen/windows/mednafen.exe",
                    "linux": "Mednafen/linux/Mednafen.AppImage"
                },
                "save_dir": {
                    "windows": "Mednafen/windows/sav",
                    "linux": "Mednafen/linux/Mednafen.AppImage.home/.mednafen/sav"
                },
                "setup_dir": {
                    "windows": "Mednafen/windows",
                    "linux": "Mednafen/linux/Mednafen.AppImage.home/.mednafen"
                },
                "config_file": {
                    "windows": "Mednafen/windows/mednafen.cfg",
                    "linux": "Mednafen/linux/Mednafen.AppImage.home/.mednafen/mednafen.cfg"
                },
                "run_sandboxed": {
                    "windows": False,
                    "linux": False
                }
            }
        }

    # Setup
    def Setup(self, verbose = False, exit_on_failure = False):

        # Download program
        if programs.ShouldProgramBeInstalled("Mednafen", "windows"):
            success = release.DownloadWebpageRelease(
                webpage_url = "https://mednafen.github.io/",
                starts_with = "https://mednafen.github.io/releases/files/mednafen",
                ends_with = "UNSTABLE-win64.zip",
                search_file = "mednafen.exe",
                install_name = "Mednafen",
                install_dir = programs.GetProgramInstallDir("Mednafen", "windows"),
                backups_dir = programs.GetProgramBackupDir("Mednafen", "windows"),
                release_type = config.release_type_archive,
                get_latest = True,
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup Mednafen")

        # Build program
        if programs.ShouldProgramBeInstalled("Mednafen", "linux"):
            success = release.BuildAppImageFromSource(
                webpage_url = "https://mednafen.github.io/",
                starts_with = "https://mednafen.github.io/releases/files/mednafen",
                ends_with = "UNSTABLE.tar.xz",
                install_name = "Mednafen",
                install_dir = programs.GetProgramInstallDir("Mednafen", "linux"),
                backups_dir = programs.GetProgramBackupDir("Mednafen", "linux"),
                build_cmd = [
                    "cd", "mednafen",
                    "&&",
                    "./configure",
                    "&&",
                    "make", "-j", "4"
                ],
                internal_copies = [
                    {"from": "Source/mednafen/src/mednafen", "to": "AppImage/usr/bin/mednafen"},
                    {"from": "AppImageTool/linux/app.desktop", "to": "AppImage/app.desktop"},
                    {"from": "AppImageTool/linux/icon.svg", "to": "AppImage/icon.svg"}
                ],
                internal_symlinks = [
                    {"from": "usr/bin/mednafen", "to": "AppRun"}
                ],
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup Mednafen")

        # Create config files
        for config_filename, config_contents in config_files.items():
            success = system.TouchFile(
                src = os.path.join(environment.GetEmulatorsRootDir(), config_filename),
                contents = config_contents.strip(),
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup Mednafen config files")

        # Verify system files
        for filename, expected_md5 in system_files.items():
            actual_md5 = hashing.CalculateFileMD5(
                filename = os.path.join(environment.GetSyncedGameEmulatorSetupDir("Mednafen"), filename),
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            success = (expected_md5 == actual_md5)
            system.AssertCondition(success, "Could not verify Mednafen system file %s" % filename)

        # Copy system files
        for filename in system_files.keys():
            for platform in ["windows", "linux"]:
                success = system.SmartCopy(
                    src = os.path.join(environment.GetSyncedGameEmulatorSetupDir("Mednafen"), filename),
                    dest = os.path.join(programs.GetEmulatorPathConfigValue("Mednafen", "setup_dir", platform), filename),
                    verbose = verbose,
                    exit_on_failure = exit_on_failure)
                system.AssertCondition(success, "Could not setup Mednafen system files")

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
            programs.GetEmulatorProgram("Mednafen"),
            config.token_game_file
        ]

        # Launch game
        emulatorcommon.SimpleLaunch(
            game_info = game_info,
            launch_cmd = launch_cmd,
            capture_type = capture_type,
            verbose = verbose,
            exit_on_failure = exit_on_failure)
