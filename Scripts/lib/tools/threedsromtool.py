# Imports
import os, os.path
import sys

# Local imports
import config
import network
import programs
import toolbase

# ThreeDSRomTool tool
class ThreeDSRomTool(toolbase.ToolBase):

    # Get name
    def GetName(self):
        return "3DSRomTool"

    # Get config
    def GetConfig(self):
        return {
            "3DSRomTool": {
                "program": {
                    "windows": "3DSRomTool/windows/rom_tool.exe",
                    "linux": "3DSRomTool/linux/3DSRomTool.AppImage"
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
        if programs.ShouldProgramBeInstalled("3DSRomTool", "windows"):
            success = network.DownloadLatestGithubRelease(
                github_user = "NearlyTRex",
                github_repo = "3DSRomTool",
                starts_with = "rom_tool",
                ends_with = ".zip",
                search_file = "rom_tool.exe",
                install_name = "3DSRomTool",
                install_dir = programs.GetProgramInstallDir("3DSRomTool", "windows"),
                install_files = ["rom_tool.exe"],
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup 3DSRomTool")

        # Build linux program
        if programs.ShouldProgramBeInstalled("3DSRomTool", "linux"):
            success = network.BuildAppImageFromSource(
                release_url = "https://github.com/NearlyTRex/3DSRomTool.git",
                output_name = "3DSRomTool",
                output_dir = programs.GetProgramInstallDir("3DSRomTool", "linux"),
                build_cmd = [
                    "cd", "rom_tool",
                    "&&",
                    "make", "-j", "4"
                ],
                internal_copies = [
                    {"from": "Source/rom_tool/rom_tool", "to": "AppImage/usr/bin/rom_tool"},
                    {"from": "AppImageTool/linux/app.desktop", "to": "AppImage/app.desktop"},
                    {"from": "AppImageTool/linux/icon.svg", "to": "AppImage/icon.svg"}
                ],
                internal_symlinks = [
                    {"from": "usr/bin/rom_tool", "to": "AppRun"}
                ],
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup 3DSRomTool")
