# Imports
import os, os.path
import sys

# Local imports
import config
import system
import release
import programs
import toolbase

# Config files
config_files = {}

# MameTools tool
class MameTools(toolbase.ToolBase):

    # Get name
    def GetName(self):
        return "MameTools"

    # Get config
    def GetConfig(self):

        # MameChdman
        return {
            "MameChdman": {
                "program": {
                    "windows": "MameChdman/windows/chdman.exe",
                    "linux": "MameChdman/linux/MameChdman.AppImage"
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
        if programs.ShouldProgramBeInstalled("MameChdman", "windows"):
            success = release.DownloadGithubRelease(
                github_user = "mamedev",
                github_repo = "mame",
                starts_with = "mame",
                ends_with = "64bit.exe",
                search_file = "chdman.exe",
                install_name = "MameChdman",
                install_dir = programs.GetProgramInstallDir("MameChdman", "windows"),
                backups_dir = programs.GetProgramBackupDir("MameChdman", "windows"),
                install_files = ["chdman.exe"],
                installer_type = config.InstallerType.SEVENZIP,
                release_type = config.ReleaseType.ARCHIVE,
                get_latest = True,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup MameChdman")

        # Build linux program
        if programs.ShouldProgramBeInstalled("MameChdman", "linux"):
            success = release.BuildAppImageFromSource(
                release_url = "https://github.com/NearlyTRex/Mame.git",
                output_file = "App-x86_64.AppImage",
                install_name = "MameChdman",
                install_dir = programs.GetProgramInstallDir("MameChdman", "linux"),
                backups_dir = programs.GetProgramBackupDir("MameChdman", "linux"),
                build_cmd = [
                    "make", "TOOLS=1", "EMULATOR=0", "-j5"
                ],
                internal_copies = [
                    {"from": "Source/chdman", "to": "AppImage/usr/bin/chdman"},
                    {"from": "AppImageTool/linux/app.desktop", "to": "AppImage/app.desktop"},
                    {"from": "AppImageTool/linux/icon.svg", "to": "AppImage/icon.svg"}
                ],
                internal_symlinks = [
                    {"from": "usr/bin/chdman", "to": "AppRun"}
                ],
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup MameChdman")

    # Setup offline
    def SetupOffline(self, verbose = False, pretend_run = False, exit_on_failure = False):

        # Setup windows program
        if programs.ShouldProgramBeInstalled("MameChdman", "windows"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetProgramBackupDir("MameChdman", "windows"),
                install_name = "MameChdman",
                install_dir = programs.GetProgramInstallDir("MameChdman", "windows"),
                search_file = "chdman.exe",
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup MameChdman")

        # Setup linux program
        if programs.ShouldProgramBeInstalled("MameChdman", "linux"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetProgramBackupDir("MameChdman", "linux"),
                install_name = "MameChdman",
                install_dir = programs.GetProgramInstallDir("MameChdman", "linux"),
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup MameChdman")
