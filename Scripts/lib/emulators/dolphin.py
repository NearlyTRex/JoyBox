# Imports
import os, os.path
import sys

# Local imports
import config
import environment
import system
import release
import programs
import hashing
import archive
import nintendo
import gui
import emulatorcommon
import emulatorbase

# Config files
config_files = {}
config_files["Dolphin/windows/portable.txt"] = ""
config_files["Dolphin/windows/User/Config/Dolphin.ini"] = ""
config_files["Dolphin/linux/Dolphin.AppImage.home/.config/dolphin-emu/Dolphin.ini"] = ""

# System files
system_files = {}
system_files["Wii.zip"] = "2029efb1ed06ef0cb3679537b803d9ab"

# Dolphin emulator
class Dolphin(emulatorbase.EmulatorBase):

    # Get name
    def GetName(self):
        return "Dolphin"

    # Get platforms
    def GetPlatforms(self):
        return [
            config.game_subcategory_nintendo_gamecube,
            config.game_subcategory_nintendo_wii
        ]

    # Get config
    def GetConfig(self):
        return {
            "Dolphin": {
                "program": {
                    "windows": "Dolphin/windows/Dolphin.exe",
                    "linux": "Dolphin/linux/Dolphin.AppImage"
                },
                "save_dir": {
                    "windows": None,
                    "linux": None
                },
                "save_base_dir": {
                    "windows": "Dolphin/windows/User",
                    "linux": "Dolphin/linux/Dolphin.AppImage.home/.local/share/dolphin-emu"
                },
                "save_sub_dirs": {

                    # Nintendo
                    config.game_subcategory_nintendo_gamecube: "GC",
                    config.game_subcategory_nintendo_wii: "Wii/title/00010000"
                },
                "setup_dir": {
                    "windows": "Dolphin/windows/User",
                    "linux": "Dolphin/linux/Dolphin.AppImage.home/.local/share/dolphin-emu"
                },
                "config_file": {
                    "windows": "Dolphin/windows/User/Config/Dolphin.ini",
                    "linux": "Dolphin/linux/Dolphin.AppImage.home/.config/dolphin-emu/Dolphin.ini"
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
                for wad_file in system.BuildFileListByExtensions(package_dir, extensions = [".wad"]):
                    pass
        return True

    # Setup
    def Setup(self, verbose = False, exit_on_failure = False):

        # Download windows program
        if programs.ShouldProgramBeInstalled("Dolphin", "windows"):
            success = release.DownloadWebpageRelease(
                webpage_url = "https://dolphin-emu.org/download/",
                starts_with = "https://dl.dolphin-emu.org/builds",
                ends_with = "x64.7z",
                search_file = "Dolphin.exe",
                install_name = "Dolphin",
                install_dir = programs.GetProgramInstallDir("Dolphin", "windows"),
                backups_dir = programs.GetProgramBackupDir("Dolphin", "windows"),
                get_latest = True,
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup Dolphin")

        # Build linux program
        if programs.ShouldProgramBeInstalled("Dolphin", "linux"):
            success = release.BuildAppImageFromSource(
                release_url = "https://github.com/NearlyTRex/Dolphin.git",
                output_name = "Dolphin",
                output_dir = programs.GetProgramInstallDir("Dolphin", "linux"),
                build_cmd = [
                    "cmake", "..", "-DLINUX_LOCAL_DEV=true", "-DCMAKE_BUILD_TYPE=Release",
                    "&&",
                    "make", "-j", "4"
                ],
                build_dir = "Build",
                internal_copies = [
                    {"from": "Source/Build/Binaries/dolphin-emu", "to": "AppImage/usr/bin/dolphin-emu"},
                    {"from": "Source/Build/Binaries/dolphin-tool", "to": "AppImage/usr/bin/dolphin-tool"},
                    {"from": "Source/Data/Sys", "to": "AppImage/usr/bin/Sys"},
                    {"from": "Source/Data/dolphin-emu.desktop", "to": "AppImage/dolphin-emu.desktop"},
                    {"from": "Source/Data/dolphin-emu.png", "to": "AppImage/dolphin-emu.png"}
                ],
                internal_symlinks = [
                    {"from": "usr/bin/dolphin-emu", "to": "AppRun"}
                ],
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup Dolphin")

        # Create config files
        for config_filename, config_contents in config_files.items():
            success = system.TouchFile(
                src = os.path.join(environment.GetEmulatorsRootDir(), config_filename),
                contents = config_contents.strip(),
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup Dolphin config files")

        # Verify system files
        for filename, expected_md5 in system_files.items():
            actual_md5 = hashing.CalculateFileMD5(
                filename = os.path.join(environment.GetSyncedGameEmulatorSetupDir("Dolphin"), filename),
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            success = (expected_md5 == actual_md5)
            system.AssertCondition(success, "Could not verify Dolphin system file %s" % filename)

        # Extract system files
        for platform in ["windows", "linux"]:
            for obj in ["Wii"]:
                if os.path.exists(os.path.join(environment.GetSyncedGameEmulatorSetupDir("Dolphin"), obj + ".zip")):
                    success = archive.ExtractArchive(
                        archive_file = os.path.join(environment.GetSyncedGameEmulatorSetupDir("Dolphin"), obj + ".zip"),
                        extract_dir = os.path.join(programs.GetEmulatorPathConfigValue("Dolphin", "setup_dir", platform), obj),
                        skip_existing = True,
                        verbose = verbose,
                        exit_on_failure = exit_on_failure)
                    system.AssertCondition(success, "Could not extract Dolphin system files")

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
            programs.GetEmulatorProgram("Dolphin"),
            config.token_game_file
        ]
        if fullscreen:
            launch_cmd += [
                "--config", "Dolphin.Display.Fullscreen=True"
            ]

        # Launch game
        emulatorcommon.SimpleLaunch(
            game_info = game_info,
            launch_cmd = launch_cmd,
            capture_type = capture_type,
            verbose = verbose,
            exit_on_failure = exit_on_failure)
