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

# FFMpeg tool
class FFMpeg(base.ToolBase):

    # Get name
    def GetName(self):
        return "FFMpeg"

    # Get config
    def GetConfig(self):
        return {
            "FFMpeg": {
                "program": {
                    "windows": "FFMpeg/windows/ffmpeg.exe",
                    "linux": "FFMpeg/linux/ffmpeg"
                },
                "run_sandboxed": {
                    "windows": False,
                    "linux": False
                }
            }
        }

    # Download
    def Download(self, force_downloads = False, verbose = False, exit_on_failure = False):
        if force_downloads or programs.ShouldProgramBeInstalled("FFMpeg", "windows"):
            network.DownloadLatestGithubRelease(
                github_user = "BtbN",
                github_repo = "FFmpeg-Builds",
                starts_with = "ffmpeg-master-latest",
                ends_with = "win64-gpl.zip",
                search_file = "ffmpeg.exe",
                install_name = "FFMpeg",
                install_dir = programs.GetProgramInstallDir("FFMpeg", "windows"),
                install_files = ["ffmpeg.exe"],
                verbose = verbose,
                exit_on_failure = exit_on_failure)
        if force_downloads or programs.ShouldProgramBeInstalled("FFMpeg", "linux"):
            network.DownloadLatestGithubRelease(
                github_user = "BtbN",
                github_repo = "FFmpeg-Builds",
                starts_with = "ffmpeg-master-latest",
                ends_with = "linux64-gpl.tar.xz",
                search_file = "ffmpeg",
                install_name = "FFMpeg",
                install_dir = programs.GetProgramInstallDir("FFMpeg", "linux"),
                install_files = ["ffmpeg"],
                verbose = verbose,
                exit_on_failure = exit_on_failure)
