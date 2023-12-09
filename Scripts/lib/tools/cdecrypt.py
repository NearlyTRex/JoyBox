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

# CDecrypt tool
class CDecrypt(base.ToolBase):

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

    # Download
    def Download(self, force_downloads = False, verbose = False, exit_on_failure = False):
        if force_downloads or programs.ShouldProgramBeInstalled("CDecrypt", "windows"):
            network.DownloadLatestGithubRelease(
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
        if force_downloads or programs.ShouldProgramBeInstalled("CDecrypt", "linux"):
            network.BuildAppImageFromSource(
                release_url = "https://github.com/NearlyTRex/CDecrypt.git",
                output_name = "CDecrypt",
                output_dir = programs.GetProgramInstallDir("CDecrypt", "linux"),
                build_cmd = [
                    "make", "-j", "4"
                ],
                internal_copies = [
                    {"from": "Source/cdecrypt", "to": "AppImage/usr/bin/cdecrypt"},
                    {"from": "AppImageTool/linux/app.desktop", "to": "AppImage/app.desktop"},
                    {"from": "AppImageTool/linux/icon.png", "to": "AppImage/icon.png"}
                ],
                internal_symlinks = [
                    {"from": "usr/bin/cdecrypt", "to": "AppRun"}
                ],
                verbose = verbose,
                exit_on_failure = exit_on_failure)
