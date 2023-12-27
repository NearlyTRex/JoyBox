# Imports
import os, os.path
import sys

# Local imports
import config
import system
import network
import programs
import toolbase

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
    def Setup(self, verbose = False, exit_on_failure = False):

        # Download windows program
        if programs.ShouldProgramBeInstalled("HacTool", "windows"):
            success = network.DownloadLatestGithubRelease(
                github_user = "SciresM",
                github_repo = "hactool",
                starts_with = "hactool",
                ends_with = "win.zip",
                search_file = "hactool.exe",
                install_name = "HacTool",
                install_dir = programs.GetProgramInstallDir("HacTool", "windows"),
                install_files = ["hactool.exe"],
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup HacTool")

        # Build linux program
        if programs.ShouldProgramBeInstalled("HacTool", "linux"):
            success = network.BuildAppImageFromSource(
                release_url = "https://github.com/NearlyTRex/HacTool.git",
                output_name = "HacTool",
                output_dir = programs.GetProgramInstallDir("HacTool", "linux"),
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
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup HacTool")
