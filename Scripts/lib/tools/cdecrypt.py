# Imports
import os, os.path
import sys

# Local imports
import config
import system
import network
import programs
import toolbase

# Config files
config_files = {}

# CDecrypt tool
class CDecrypt(toolbase.ToolBase):

    # Get name
    def GetName(self):
        return "CDecrypt"

    # Get config
    def GetConfig(self):
        return {
            "CDecrypt": {
                "program": {
                    "windows": "CDecrypt/windows/cdecrypt.exe",
                    "linux": "CDecrypt/linux/CDecrypt.AppImage"
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
        if programs.ShouldProgramBeInstalled("CDecrypt", "windows"):
            success = network.DownloadLatestGithubRelease(
                github_user = "VitaSmith",
                github_repo = "cdecrypt",
                starts_with = "cdecrypt",
                ends_with = ".zip",
                search_file = "cdecrypt.exe",
                install_name = "CDecrypt",
                install_dir = programs.GetProgramInstallDir("CDecrypt", "windows"),
                install_files = ["cdecrypt.exe"],
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup CDecrypt")

        # Build linux program
        if programs.ShouldProgramBeInstalled("CDecrypt", "linux"):
            success = network.BuildAppImageFromSource(
                release_url = "https://github.com/NearlyTRex/CDecrypt.git",
                output_name = "CDecrypt",
                output_dir = programs.GetProgramInstallDir("CDecrypt", "linux"),
                build_cmd = [
                    "make", "-j", "4"
                ],
                internal_copies = [
                    {"from": "Source/cdecrypt", "to": "AppImage/usr/bin/cdecrypt"},
                    {"from": "AppImageTool/linux/app.desktop", "to": "AppImage/app.desktop"},
                    {"from": "AppImageTool/linux/icon.svg", "to": "AppImage/icon.svg"}
                ],
                internal_symlinks = [
                    {"from": "usr/bin/cdecrypt", "to": "AppRun"}
                ],
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup CDecrypt")
