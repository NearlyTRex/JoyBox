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

# ExtractXIso tool
class ExtractXIso(toolbase.ToolBase):

    # Get name
    def GetName(self):
        return "ExtractXIso"

    # Get config
    def GetConfig(self):
        return {
            "ExtractXIso": {
                "program": {
                    "windows": "ExtractXIso/windows/extract-xiso.exe",
                    "linux": "ExtractXIso/linux/ExtractXIso.AppImage"
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
        if programs.ShouldProgramBeInstalled("ExtractXIso", "windows"):
            success = release.DownloadGithubRelease(
                github_user = "XboxDev",
                github_repo = "extract-xiso",
                starts_with = "extract-xiso",
                ends_with = "win32-release.zip",
                search_file = "extract-xiso.exe",
                install_name = "ExtractXIso",
                install_dir = programs.GetProgramInstallDir("ExtractXIso", "windows"),
                backups_dir = programs.GetProgramBackupDir("ExtractXIso", "windows"),
                install_files = ["extract-xiso.exe"],
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup ExtractXIso")

        # Build linux program
        if programs.ShouldProgramBeInstalled("ExtractXIso", "linux"):
            success = release.BuildAppImageFromSource(
                release_url = "https://github.com/NearlyTRex/ExtractXIso.git",
                output_file = "App-x86_64.AppImage",
                install_name = "ExtractXIso",
                install_dir = programs.GetProgramInstallDir("ExtractXIso", "linux"),
                backups_dir = programs.GetProgramBackupDir("ExtractXIso", "linux"),
                build_cmd = [
                    "cmake", "..",
                    "&&",
                    "make"
                ],
                build_dir = "Build",
                internal_copies = [
                    {"from": "Source/Build/extract-xiso", "to": "AppImage/usr/bin/extract-xiso"},
                    {"from": "AppImageTool/linux/app.desktop", "to": "AppImage/app.desktop"},
                    {"from": "AppImageTool/linux/icon.svg", "to": "AppImage/icon.svg"}
                ],
                internal_symlinks = [
                    {"from": "usr/bin/extract-xiso", "to": "AppRun"}
                ],
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup ExtractXIso")

    # Setup offline
    def SetupOffline(self, verbose = False, pretend_run = False, exit_on_failure = False):

        # Setup windows program
        if programs.ShouldProgramBeInstalled("ExtractXIso", "windows"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetProgramBackupDir("ExtractXIso", "windows"),
                install_name = "ExtractXIso",
                install_dir = programs.GetProgramInstallDir("ExtractXIso", "windows"),
                search_file = "extract-xiso.exe",
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup ExtractXIso")

        # Setup linux program
        if programs.ShouldProgramBeInstalled("ExtractXIso", "linux"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetProgramBackupDir("ExtractXIso", "linux"),
                install_name = "ExtractXIso",
                install_dir = programs.GetProgramInstallDir("ExtractXIso", "linux"),
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup ExtractXIso")
