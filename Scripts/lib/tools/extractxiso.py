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
    def Setup(self, verbose = False, exit_on_failure = False):

        # Download windows program
        if programs.ShouldProgramBeInstalled("ExtractXIso", "windows"):
            success = network.DownloadLatestGithubRelease(
                github_user = "XboxDev",
                github_repo = "extract-xiso",
                starts_with = "extract-xiso",
                ends_with = "win32-release.zip",
                search_file = "extract-xiso.exe",
                install_name = "ExtractXIso",
                install_dir = programs.GetProgramInstallDir("ExtractXIso", "windows"),
                install_files = ["extract-xiso.exe"],
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup ExtractXIso")

        # Build linux program
        if programs.ShouldProgramBeInstalled("ExtractXIso", "linux"):
            success = network.BuildAppImageFromSource(
                release_url = "https://github.com/NearlyTRex/ExtractXIso.git",
                output_name = "ExtractXIso",
                output_dir = programs.GetProgramInstallDir("ExtractXIso", "linux"),
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
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup ExtractXIso")
