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
import gui
import emulatorcommon
import emulatorbase

# Config files
config_files = {}
config_file_general = """
[config]
amiga_model = A500
governor_warning = 0
"""
config_files["FS-UAE/windows/Portable.ini"] = ""
config_files["FS-UAE/windows/Configurations/Default.fs-uae"] = config_file_general
config_files["FS-UAE/linux/FS-UAE.AppImage.home/FS-UAE/Configurations/Default.fs-uae"] = config_file_general

# System files
system_files = {}
system_files["Kickstarts/kick40068.A1200"] = "646773759326fbac3b2311fd8c8793ee"
system_files["Kickstarts/kick34005.A500"] = "82a21c1890cae844b3df741f2762d48d"
system_files["Kickstarts/kick40063.A600"] = "e40a5dfb3d017ba8779faba30cbd1c8e"

# FSUAE emulator
class FSUAE(emulatorbase.EmulatorBase):

    # Get name
    def GetName(self):
        return "FS-UAE"

    # Get platforms
    def GetPlatforms(self):
        return [
            config.game_subcategory_commodore_amiga
        ]

    # Get config
    def GetConfig(self):
        return {
            "FS-UAE": {
                "program": {
                    "windows": "FS-UAE/windows/Windows/x86-64/fs-uae.exe",
                    "linux": "FS-UAE/linux/FS-UAE.AppImage"
                },
                "save_dir": {
                    "windows": None,
                    "linux": None
                },
                "setup_dir": {
                    "windows": "FS-UAE/windows",
                    "linux": "FS-UAE/linux/FS-UAE.AppImage.home/FS-UAE"
                },
                "config_file": {
                    "windows": "FS-UAE/windows/Configurations/Default.fs-uae",
                    "linux": "FS-UAE/linux/FS-UAE.AppImage.home/FS-UAE/Configurations/Default.fs-uae"
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
        if programs.ShouldProgramBeInstalled("FS-UAE", "windows"):
            success = release.DownloadGithubRelease(
                github_user = "FrodeSolheim",
                github_repo = "fs-uae",
                starts_with = "FS-UAE",
                ends_with = "Windows_x86-64.zip",
                search_file = "Plugin.ini",
                install_name = "FS-UAE",
                install_dir = programs.GetProgramInstallDir("FS-UAE", "windows"),
                backups_dir = programs.GetProgramBackupDir("FS-UAE", "windows"),
                get_latest = True,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup FS-UAE")

        # Build linux program
        if programs.ShouldProgramBeInstalled("FS-UAE", "linux"):
            success = release.BuildReleaseFromSource(
                release_url = "https://github.com/FrodeSolheim/fs-uae/releases/download/v3.1.66/fs-uae-3.1.66.tar.xz",
                output_file = "FS-UAE-x86_64.AppImage",
                install_name = "FS-UAE",
                install_dir = programs.GetProgramInstallDir("FS-UAE", "linux"),
                backups_dir = programs.GetProgramBackupDir("FS-UAE", "linux"),
                build_cmd = [
                    "cd", "fs-uae-3.1.66",
                    "&&",
                    "./configure",
                    "&&",
                    "make", "-j", "8"
                ],
                internal_copies = [
                    {"from": "Source/fs-uae-3.1.66/fs-uae", "to": "AppImage/usr/bin/fs-uae"},
                    {"from": "Source/fs-uae-3.1.66/share/applications/fs-uae.desktop", "to": "AppImage/app.desktop"},
                    {"from": "Source/fs-uae-3.1.66/share/icons/hicolor/256x256/apps/fs-uae.png", "to": "AppImage/fs-uae.png"}
                ],
                internal_symlinks = [
                    {"from": "usr/bin/fs-uae", "to": "AppRun"}
                ],
                external_copies = [
                    {"from": "Source/fs-uae-3.1.66/fs-uae.dat", "to": "fs-uae.dat"}
                ],
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup FS-UAE")

    # Setup offline
    def SetupOffline(self, verbose = False, pretend_run = False, exit_on_failure = False):

        # Setup windows program
        if programs.ShouldProgramBeInstalled("FS-UAE", "windows"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetProgramBackupDir("FS-UAE", "windows"),
                install_name = "FS-UAE",
                install_dir = programs.GetProgramInstallDir("FS-UAE", "windows"),
                search_file = "Plugin.ini",
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup FS-UAE")

        # Setup linux program
        if programs.ShouldProgramBeInstalled("FS-UAE", "linux"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetProgramBackupDir("FS-UAE", "linux"),
                install_name = "FS-UAE",
                install_dir = programs.GetProgramInstallDir("FS-UAE", "linux"),
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup FS-UAE")

    # Configure
    def Configure(self, verbose = False, pretend_run = False, exit_on_failure = False):

        # Create config files
        for config_filename, config_contents in config_files.items():
            success = system.TouchFile(
                src = os.path.join(environment.GetEmulatorsRootDir(), config_filename),
                contents = config_contents.strip(),
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup FS-UAE config files")

        # Verify system files
        for filename, expected_md5 in system_files.items():
            actual_md5 = hashing.CalculateFileMD5(
                filename = os.path.join(environment.GetLockerGamingEmulatorSetupDir("FS-UAE"), filename),
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            success = (expected_md5 == actual_md5)
            system.AssertCondition(success, "Could not verify FS-UAE system file %s" % filename)

        # Copy system files
        for filename in system_files.keys():
            for platform in ["windows", "linux"]:
                success = system.SmartCopy(
                    src = os.path.join(environment.GetLockerGamingEmulatorSetupDir("FS-UAE"), filename),
                    dest = os.path.join(programs.GetEmulatorPathConfigValue("FS-UAE", "setup_dir", platform), filename),
                    verbose = verbose,
                    pretend_run = pretend_run,
                    exit_on_failure = exit_on_failure)
                system.AssertCondition(success, "Could not setup FS-UAE system files")

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
            programs.GetEmulatorProgram("FS-UAE"),
            config.token_game_file
        ]
        if fullscreen:
            launch_cmd += [
                "--fullscreen=1"
            ]

        # Launch game
        emulatorcommon.SimpleLaunch(
            game_info = game_info,
            launch_cmd = launch_cmd,
            capture_type = capture_type,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
