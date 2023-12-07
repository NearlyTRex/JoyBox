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

# PS3Dec tool
class PS3Dec(base.ToolBase):

    # Get name
    def GetName():
        return "PS3Dec"

    # Get config
    def GetConfig():
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

    # Download
    def Download(force_downloads = False):
        if force_downloads or programs.ShouldProgramBeInstalled("PS3Dec", "windows"):
            network.DownloadLatestGithubRelease(
                github_user = "NearlyTRex",
                github_repo = "PS3Dec",
                starts_with = "PS3Dec",
                ends_with = ".zip",
                search_file = "PS3Dec.exe",
                install_name = "PS3Dec",
                install_dir = programs.GetProgramInstallDir("PS3Dec", "windows"),
                install_files = ["PS3Dec.exe"],
                verbose = config.default_flag_verbose,
                exit_on_failure = config.default_flag_exit_on_failure)
        if force_downloads or programs.ShouldProgramBeInstalled("PS3Dec", "linux"):
            network.BuildAppImageFromSource(
                release_url = "https://github.com/NearlyTRex/PS3Dec.git",
                output_name = "PS3Dec",
                output_dir = programs.GetProgramInstallDir("PS3Dec", "linux"),
                build_cmd = [
                    "cmake", "-G", "Ninja", "..",
                    "&&",
                    "ninja"
                ],
                build_dir = "Build",
                internal_copies = [
                    {"from": "Source/Build/Release/PS3Dec", "to": "AppImage/usr/bin/PS3Dec"},
                    {"from": "AppImageTool/linux/app.desktop", "to": "AppImage/app.desktop"},
                    {"from": "AppImageTool/linux/icon.png", "to": "AppImage/icon.png"}
                ],
                internal_symlinks = [
                    {"from": "usr/bin/PS3Dec", "to": "AppRun"}
                ],
                verbose = config.default_flag_verbose,
                exit_on_failure = config.default_flag_exit_on_failure)
