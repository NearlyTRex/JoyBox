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

# PS3Dec tool
class PS3Dec(toolbase.ToolBase):

    # Get name
    def GetName(self):
        return "PS3Dec"

    # Get config
    def GetConfig(self):
        return {
            "PS3Dec": {
                "program": {
                    "windows": "PS3Dec/windows/PS3Dec.exe",
                    "linux": "PS3Dec/linux/PS3Dec.AppImage"
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
        if programs.ShouldProgramBeInstalled("PS3Dec", "windows"):
            success = release.DownloadGithubRelease(
                github_user = "NearlyTRex",
                github_repo = "PS3Dec",
                starts_with = "PS3Dec",
                ends_with = ".zip",
                search_file = "PS3Dec.exe",
                install_name = "PS3Dec",
                install_dir = programs.GetProgramInstallDir("PS3Dec", "windows"),
                backups_dir = programs.GetProgramBackupDir("PS3Dec", "windows"),
                install_files = ["PS3Dec.exe"],
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                system.LogError("Could not setup PS3Dec")
                return False

        # Build linux program
        if programs.ShouldProgramBeInstalled("PS3Dec", "linux"):
            success = release.BuildAppImageFromSource(
                release_url = "https://github.com/NearlyTRex/PS3Dec.git",
                output_file = "App-x86_64.AppImage",
                install_name = "PS3Dec",
                install_dir = programs.GetProgramInstallDir("PS3Dec", "linux"),
                backups_dir = programs.GetProgramBackupDir("PS3Dec", "linux"),
                build_cmd = [
                    "cmake", "-G", "Ninja", "..",
                    "&&",
                    "ninja"
                ],
                build_dir = "Build",
                internal_copies = [
                    {"from": "Source/Build/Release/PS3Dec", "to": "AppImage/usr/bin/PS3Dec"},
                    {"from": "AppImageTool/linux/app.desktop", "to": "AppImage/app.desktop"},
                    {"from": "AppImageTool/linux/icon.svg", "to": "AppImage/icon.svg"}
                ],
                internal_symlinks = [
                    {"from": "usr/bin/PS3Dec", "to": "AppRun"}
                ],
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                system.LogError("Could not setup PS3Dec")
                return False
        return True

    # Setup offline
    def SetupOffline(self, verbose = False, pretend_run = False, exit_on_failure = False):

        # Setup windows program
        if programs.ShouldProgramBeInstalled("PS3Dec", "windows"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetProgramBackupDir("PS3Dec", "windows"),
                install_name = "PS3Dec",
                install_dir = programs.GetProgramInstallDir("PS3Dec", "windows"),
                search_file = "PS3Dec.exe",
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                system.LogError("Could not setup PS3Dec")
                return False

        # Setup linux program
        if programs.ShouldProgramBeInstalled("PS3Dec", "linux"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetProgramBackupDir("PS3Dec", "linux"),
                install_name = "PS3Dec",
                install_dir = programs.GetProgramInstallDir("PS3Dec", "linux"),
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                system.LogError("Could not setup PS3Dec")
                return False
        return True
