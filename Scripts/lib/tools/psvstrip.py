# Imports
import os, os.path
import sys

# Local imports
import config
import network
import programs
import toolbase

# PSVStrip tool
class PSVStrip(toolbase.ToolBase):

    # Get name
    def GetName(self):
        return "PSVStrip"

    # Get config
    def GetConfig(self):
        return {
            "PSVStrip": {
                "program": {
                    "windows": "PSVStrip/windows/psvstrip.exe",
                    "linux": "PSVStrip/windows/psvstrip.exe"
                },
                "run_sandboxed": {
                    "windows": False,
                    "linux": True
                }
            }
        }

    # Download
    def Download(self, force_downloads = False, verbose = False, exit_on_failure = False):
        if force_downloads or programs.ShouldProgramBeInstalled("PSVStrip", "windows"):
            network.DownloadLatestGithubRelease(
                github_user = "Kippykip",
                github_repo = "PSVStrip",
                starts_with = "PSVStrip",
                ends_with = ".zip",
                search_file = "psvstrip.exe",
                install_name = "PSVStrip",
                install_dir = programs.GetProgramInstallDir("PSVStrip", "windows"),
                install_files = ["psvstrip.exe"],
                verbose = verbose,
                exit_on_failure = exit_on_failure)
