# Imports
import os, os.path
import sys

# Local imports
import config
import network
import programs
import toolbase

# FFMpeg tool
class FFMpeg(toolbase.ToolBase):

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

    # Setup
    def Setup(self, verbose = False, exit_on_failure = False):

        # Download windows program
        if programs.ShouldProgramBeInstalled("FFMpeg", "windows"):
            success = network.DownloadLatestGithubRelease(
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
            system.AssertCondition(success, "Could not setup FFMpeg")

        # Download linux program
        if programs.ShouldProgramBeInstalled("FFMpeg", "linux"):
            success = network.DownloadLatestGithubRelease(
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
            system.AssertCondition(success, "Could not setup FFMpeg")
