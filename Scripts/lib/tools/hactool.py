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

# HacTool tool
class HacTool(toolbase.ToolBase):

    # Get name
    def GetName(self):
        return "HacTool"

    # Get config
    def GetConfig(self):
        return {
            "HacTool": {
                "program": {
                    "windows": "HacTool/windows/hactool.exe",
                    "linux": "HacTool/linux/HacTool.AppImage"
                },
                "run_sandboxed": {
                    "windows": False,
                    "linux": False
                }
            }
        }

    # Setup
    def Setup(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Download windows program
        if programs.ShouldProgramBeInstalled("HacTool", "windows"):
            success = release.DownloadGithubRelease(
                github_user = "SciresM",
                github_repo = "hactool",
                starts_with = "hactool",
                ends_with = "win.zip",
                search_file = "hactool.exe",
                install_name = "HacTool",
                install_dir = programs.GetProgramInstallDir("HacTool", "windows"),
                backups_dir = programs.GetProgramBackupDir("HacTool", "windows"),
                install_files = ["hactool.exe"],
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                system.LogError("Could not setup HacTool")
                return False

        # Build linux program
        if programs.ShouldProgramBeInstalled("HacTool", "linux"):
            success = release.BuildAppImageFromSource(
                release_url = "https://github.com/NearlyTRex/HacTool.git",
                output_file = "App-x86_64.AppImage",
                install_name = "HacTool",
                install_dir = programs.GetProgramInstallDir("HacTool", "linux"),
                backups_dir = programs.GetProgramBackupDir("HacTool", "linux"),
                build_cmd = [
                    "cp", "config.mk.template", "config.mk",
                    "&&",
                    "make", "-j", "4"
                ],
                internal_copies = [
                    {"from": "Source/hactool", "to": "AppImage/usr/bin/hactool"},
                    {"from": "AppImageTool/linux/app.desktop", "to": "AppImage/app.desktop"},
                    {"from": "AppImageTool/linux/icon.svg", "to": "AppImage/icon.svg"}
                ],
                internal_symlinks = [
                    {"from": "usr/bin/hactool", "to": "AppRun"}
                ],
                locker_type = setup_params.locker_type,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                system.LogError("Could not setup HacTool")
                return False
        return True

    # Setup offline
    def SetupOffline(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Setup windows program
        if programs.ShouldProgramBeInstalled("HacTool", "windows"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetProgramBackupDir("HacTool", "windows"),
                install_name = "HacTool",
                install_dir = programs.GetProgramInstallDir("HacTool", "windows"),
                search_file = "hactool.exe",
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                system.LogError("Could not setup HacTool")
                return False

        # Setup linux program
        if programs.ShouldProgramBeInstalled("HacTool", "linux"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetProgramBackupDir("HacTool", "linux"),
                install_name = "HacTool",
                install_dir = programs.GetProgramInstallDir("HacTool", "linux"),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                system.LogError("Could not setup HacTool")
                return False
        return True
