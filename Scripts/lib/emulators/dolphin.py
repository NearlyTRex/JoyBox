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
config_files["Dolphin/linux/Dolphin.AppImage.home/.config/dolphin-emu/Dolphin.ini"] = """
[Analytics]
ID = db8045cccc2ce4e3eebf2a60a1ee1424
PermissionAsked = True
[NetPlay]
TraversalChoice = direct
"""
config_files["Dolphin/linux/Dolphin.AppImage.home/.config/dolphin-emu/GCPadNew.ini"] = """
[GCPad1]
Device = SDL/0/X360 Controller
Buttons/A = `Button E`
Buttons/B = `Button S`
Buttons/X = `Button N`
Buttons/Y = `Button W`
Buttons/Z = Back
Buttons/Start = Start
Main Stick/Up = `Left Y+`
Main Stick/Down = `Left Y-`
Main Stick/Left = `Left X-`
Main Stick/Right = `Left X+`
Main Stick/Modifier = `Shift`
Main Stick/Calibration = 100.00 141.42 100.00 141.42 100.00 141.42 100.00 141.42
C-Stick/Up = `Right Y+`
C-Stick/Down = `Right Y-`
C-Stick/Left = `Right X-`
C-Stick/Right = `Right X+`
C-Stick/Modifier = `Ctrl`
C-Stick/Calibration = 100.00 141.42 100.00 141.42 100.00 141.42 100.00 141.42
Triggers/L = `Trigger L`
Triggers/R = `Trigger R`
D-Pad/Up = `Pad N`
D-Pad/Down = `Pad S`
D-Pad/Left = `Pad W`
D-Pad/Right = `Pad E`
Triggers/L-Analog = `Shoulder L`
Triggers/R-Analog = `Shoulder R`
[GCPad2]
Device = XInput2/0/Virtual core pointer
[GCPad3]
Device = XInput2/0/Virtual core pointer
[GCPad4]
Device = XInput2/0/Virtual core pointer
"""
config_files["Dolphin/linux/Dolphin.AppImage.home/.config/dolphin-emu/GBA.ini"] = """
[GBA1]
Device = SDL/0/X360 Controller
Buttons/B = `Button S`
Buttons/A = `Button E`
Buttons/L = `Shoulder L`
Buttons/R = `Shoulder R`
Buttons/SELECT = Back
Buttons/START = Start
D-Pad/Up = `Pad N`
D-Pad/Down = `Pad S`
D-Pad/Left = `Pad W`
D-Pad/Right = `Pad E`
[GBA2]
Device = XInput2/0/Virtual core pointer
[GBA3]
Device = XInput2/0/Virtual core pointer
[GBA4]
Device = XInput2/0/Virtual core pointer
"""

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
            config.Platform.NINTENDO_GAMECUBE,
            config.Platform.NINTENDO_WII
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
                    config.Platform.NINTENDO_GAMECUBE: "GC",
                    config.Platform.NINTENDO_WII: "Wii/title/00010000"
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
    def InstallAddons(self, dlc_dirs = [], update_dirs = [], verbose = False, pretend_run = False, exit_on_failure = False):
        for package_dirset in [dlc_dirs, update_dirs]:
            for package_dir in package_dirset:
                for wad_file in system.BuildFileListByExtensions(package_dir, extensions = [".wad"]):
                    pass
        return True

    # Setup
    def Setup(self, verbose = False, pretend_run = False, exit_on_failure = False):

        # Download windows program
        if programs.ShouldProgramBeInstalled("Dolphin", "windows"):
            success = release.DownloadWebpageRelease(
                webpage_url = "https://dolphin-emu.org/download",
                webpage_base_url = "https://dolphin-emu.org",
                starts_with = "https://dl.dolphin-emu.org/builds",
                ends_with = "x64.7z",
                search_file = "Dolphin.exe",
                install_name = "Dolphin",
                install_dir = programs.GetProgramInstallDir("Dolphin", "windows"),
                backups_dir = programs.GetProgramBackupDir("Dolphin", "windows"),
                get_latest = True,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                system.LogError("Could not setup Dolphin")
                return False

        # Build linux program
        if programs.ShouldProgramBeInstalled("Dolphin", "linux"):
            success = release.BuildAppImageFromSource(
                release_url = "https://github.com/NearlyTRex/Dolphin.git",
                output_file = "Dolphin_Emulator-x86_64.AppImage",
                install_name = "Dolphin",
                install_dir = programs.GetProgramInstallDir("Dolphin", "linux"),
                backups_dir = programs.GetProgramBackupDir("Dolphin", "linux"),
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
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                system.LogError("Could not setup Dolphin")
                return False
        return True

    # Setup offline
    def SetupOffline(self, verbose = False, pretend_run = False, exit_on_failure = False):

        # Setup windows program
        if programs.ShouldProgramBeInstalled("Dolphin", "windows"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetProgramBackupDir("Dolphin", "windows"),
                install_name = "Dolphin",
                install_dir = programs.GetProgramInstallDir("Dolphin", "windows"),
                search_file = "Dolphin.exe",
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                system.LogError("Could not setup Dolphin")
                return False

        # Setup linux program
        if programs.ShouldProgramBeInstalled("Dolphin", "linux"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetProgramBackupDir("Dolphin", "linux"),
                install_name = "Dolphin",
                install_dir = programs.GetProgramInstallDir("Dolphin", "linux"),
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                system.LogError("Could not setup Dolphin")
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
                system.LogError("Could not setup Dolphin config files")
                return False

        # Verify system files
        for filename, expected_md5 in system_files.items():
            actual_md5 = hashing.CalculateFileMD5(
                src = system.JoinPaths(environment.GetLockerGamingEmulatorSetupDir("Dolphin"), filename),
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            success = (expected_md5 == actual_md5)
            if not success:
                system.LogError("Could not verify Dolphin system file %s" % filename)
                return False

        # Extract system files
        for platform in ["windows", "linux"]:
            for obj in ["Wii"]:
                if os.path.exists(system.JoinPaths(environment.GetLockerGamingEmulatorSetupDir("Dolphin"), obj + config.ArchiveFileType.ZIP.cval())):
                    success = archive.ExtractArchive(
                        archive_file = system.JoinPaths(environment.GetLockerGamingEmulatorSetupDir("Dolphin"), obj + config.ArchiveFileType.ZIP.cval()),
                        extract_dir = system.JoinPaths(programs.GetEmulatorPathConfigValue("Dolphin", "setup_dir", platform), obj),
                        skip_existing = True,
                        verbose = verbose,
                        pretend_run = pretend_run,
                        exit_on_failure = exit_on_failure)
                    if not success:
                        system.LogError("Could not extract Dolphin system files")
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
            programs.GetEmulatorProgram("Dolphin"),
            config.token_game_file
        ]
        if fullscreen:
            launch_cmd += [
                "--config", "Dolphin.Display.Fullscreen=True"
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
