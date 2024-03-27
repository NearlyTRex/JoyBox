# Imports
import os, os.path
import sys

# Local imports
import config
import system
import environment
import release
import programs
import toolbase

# Config files
config_files = {}

# BalenaEtcher tool
class BalenaEtcher(toolbase.ToolBase):

    # Get name
    def GetName(self):
        return "BalenaEtcher"

    # Get config
    def GetConfig(self):
        return {
            "BalenaEtcher": {
                "program": {
                    "windows": "BalenaEtcher/windows/balenaEtcher.exe",
                    "linux": "BalenaEtcher/linux/BalenaEtcher.AppImage"
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
        if programs.ShouldProgramBeInstalled("BalenaEtcher", "windows"):
            success = release.DownloadGithubRelease(
                github_user = "balena-io",
                github_repo = "etcher",
                starts_with = "balenaEtcher-win32-x64",
                ends_with = ".zip",
                search_file = "balenaEtcher.exe",
                install_name = "BalenaEtcher",
                install_dir = programs.GetProgramInstallDir("BalenaEtcher", "windows"),
                release_type = config.release_type_archive,
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup BalenaEtcher")

        # Download linux program
        if programs.ShouldProgramBeInstalled("BalenaEtcher", "linux"):
            success = release.DownloadGithubRelease(
                github_user = "balena-io",
                github_repo = "etcher",
                starts_with = "balenaEtcher",
                ends_with = ".AppImage",
                install_name = "BalenaEtcher",
                install_dir = programs.GetProgramInstallDir("BalenaEtcher", "linux"),
                release_type = config.release_type_program,
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup BalenaEtcher")

    # Setup offline
    def SetupOffline(self, verbose = False, exit_on_failure = False):
        pass
