# Imports
import os, os.path
import sys

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.append(lib_folder)
import config
import network
import programs

# Local imports
from . import base

# ThreeDSRomTool tool
class ThreeDSRomTool(base.ToolBase):

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

    # Download
    def Download(self, force_downloads = False):
        if force_downloads or programs.ShouldProgramBeInstalled("3DSRomTool", "windows"):
            network.DownloadLatestGithubRelease(
                github_user = "NearlyTRex",
                github_repo = "3DSRomTool",
                starts_with = "rom_tool",
                ends_with = ".zip",
                search_file = "rom_tool.exe",
                install_name = "3DSRomTool",
                install_dir = programs.GetProgramInstallDir("3DSRomTool", "windows"),
                install_files = ["rom_tool.exe"],
                verbose = config.default_flag_verbose,
                exit_on_failure = config.default_flag_exit_on_failure)
        if force_downloads or programs.ShouldProgramBeInstalled("3DSRomTool", "linux"):
            network.BuildAppImageFromSource(
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
                    {"from": "AppImageTool/linux/icon.png", "to": "AppImage/icon.png"}
                ],
                internal_symlinks = [
                    {"from": "usr/bin/rom_tool", "to": "AppRun"}
                ],
                verbose = config.default_flag_verbose,
                exit_on_failure = config.default_flag_exit_on_failure)
