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
config_file_general = """
[Data%20Storage]
nand_directory=EMULATOR_SETUP_ROOT/nand/
sdmc_directory=EMULATOR_SETUP_ROOT/sdmc/

[UI]
Paths\screenshotPath=EMULATOR_SETUP_ROOT/screenshots/
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
            config.Platform.NINTENDO_3DS,
            config.Platform.NINTENDO_3DS_APPS,
            config.Platform.NINTENDO_3DS_ESHOP
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
    def InstallAddons(self, dlc_dirs = [], update_dirs = [], verbose = False, pretend_run = False, exit_on_failure = False):
        for package_dirset in [dlc_dirs, update_dirs]:
            for package_dir in package_dirset:
                for cia_file in system.BuildFileListByExtensions(package_dir, extensions = [".cia"]):
                    success = nintendo.Install3DSCIA(
                        src_3ds_file = cia_file,
                        sdmc_dir = system.JoinPaths(programs.GetEmulatorPathConfigValue("Citra", "setup_dir"), "sdmc"),
                        verbose = verbose,
                        pretend_run = pretend_run,
                        exit_on_failure = exit_on_failure)
                    if not success:
                        return False
        return True

    # Setup
    def Setup(self, verbose = False, pretend_run = False, exit_on_failure = False):

        # Setup windows program
        if programs.ShouldProgramBeInstalled("Citra", "windows"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetProgramBackupDir("Citra", "windows"),
                install_name = "Citra",
                install_dir = programs.GetProgramInstallDir("Citra", "windows"),
                search_file = "citra-qt.exe",
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                system.LogError("Could not setup Citra")
                return False

        # Setup linux program
        if programs.ShouldProgramBeInstalled("Citra", "linux"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetProgramBackupDir("Citra", "linux"),
                install_name = "Citra",
                install_dir = programs.GetProgramInstallDir("Citra", "linux"),
                search_file = "citra-qt.AppImage",
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                system.LogError("Could not setup Citra")
                return False
        return True

    # Setup offline
    def SetupOffline(self, verbose = False, pretend_run = False, exit_on_failure = False):
        self.Setup(verbose = verbose, pretend_run = pretend_run, exit_on_failure = exit_on_failure)

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
                system.LogError("Could not setup Citra config files")
                return False

        # Verify system files
        for filename, expected_md5 in system_files.items():
            actual_md5 = hashing.CalculateFileMD5(
                src = system.JoinPaths(environment.GetLockerGamingEmulatorSetupDir("Citra"), filename),
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            success = (expected_md5 == actual_md5)
            if not success:
                system.LogError("Could not verify Citra system file %s" % filename)
                return False

        # Extract system files
        for platform in ["windows", "linux"]:
            for obj in ["nand", "sysdata"]:
                if os.path.exists(system.JoinPaths(environment.GetLockerGamingEmulatorSetupDir("Citra"), obj + config.ArchiveFileType.ZIP.cval())):
                    success = archive.ExtractArchive(
                        archive_file = system.JoinPaths(environment.GetLockerGamingEmulatorSetupDir("Citra"), obj + config.ArchiveFileType.ZIP.cval()),
                        extract_dir = system.JoinPaths(programs.GetEmulatorPathConfigValue("Citra", "setup_dir", platform), obj),
                        skip_existing = True,
                        verbose = verbose,
                        pretend_run = pretend_run,
                        exit_on_failure = exit_on_failure)
                    if not success:
                        system.LogError("Could not extract Citra system files")
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
            programs.GetEmulatorProgram("Citra"),
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
