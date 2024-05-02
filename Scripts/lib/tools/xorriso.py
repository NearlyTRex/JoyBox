# Imports
import os, os.path
import sys

# Local imports
import config
import system
import network
import release
import programs
import toolbase

# Config files
config_files = {}

# XorrISO tool
class XorrISO(toolbase.ToolBase):

    # Get name
    def GetName(self):
        return "XorrISO"

    # Get config
    def GetConfig(self):
        return {
            "XorrISO": {
                "program": {
                    "windows": "XorrISO/windows/xorriso.exe",
                    "linux": "XorrISO/linux/XorrISO.AppImage"
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
        if programs.ShouldProgramBeInstalled("XorrISO", "windows"):
            success = network.DownloadGithubRepository(
                github_user = "NearlyTRex",
                github_repo = "XorrISOWindows",
                output_dir = programs.GetProgramInstallDir("XorrISO", "windows"),
                recursive = True,
                clean = True,
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup XorrISO")
            success = network.ArchiveGithubRepository(
                github_user = "NearlyTRex",
                github_repo = "XorrISOWindows",
                output_dir = programs.GetProgramBackupDir("XorrISO", "windows"),
                recursive = True,
                clean = True,
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup XorrISO")

        # Build linux program
        if programs.ShouldProgramBeInstalled("XorrISO", "linux"):
            success = release.BuildReleaseFromSource(
                release_url = "https://ftp.gnu.org/gnu/xorriso/xorriso-1.5.2.tar.gz",
                output_file = "App-x86_64.AppImage",
                install_name = "XorrISO",
                install_dir = programs.GetProgramInstallDir("XorrISO", "linux"),
                backups_dir = programs.GetProgramBackupDir("XorrISO", "linux"),
                build_cmd = [
                    "cd", "xorriso-1.5.2",
                    "./bootstrap",
                    "&&",
                    "./configure",
                    "&&",
                    "make", "-j", "4"
                ],
                internal_copies = [
                    {"from": "Source/xorriso-1.5.2/xorriso/xorriso", "to": "AppImage/usr/bin/xorriso"},
                    {"from": "AppImageTool/linux/app.desktop", "to": "AppImage/app.desktop"},
                    {"from": "AppImageTool/linux/icon.svg", "to": "AppImage/icon.svg"}
                ],
                internal_symlinks = [
                    {"from": "usr/bin/xorriso", "to": "AppRun"}
                ],
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup XorrISO")

    # Setup offline
    def SetupOffline(self, verbose = False, exit_on_failure = False):

        # Setup windows program
        if programs.ShouldProgramBeInstalled("XorrISO", "windows"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetProgramBackupDir("XorrISO", "windows"),
                install_name = "XorrISO",
                install_dir = programs.GetProgramInstallDir("XorrISO", "windows"),
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup XorrISO")

        # Setup linux program
        if programs.ShouldProgramBeInstalled("XorrISO", "linux"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetProgramBackupDir("XorrISO", "linux"),
                install_name = "XorrISO",
                install_dir = programs.GetProgramInstallDir("XorrISO", "linux"),
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup XorrISO")
