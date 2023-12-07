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

# GeckoDriver tool
class GeckoDriver(base.ToolBase):

    # Get name
    def GetName():
        return "GeckoDriver"

    # Get config
    def GetConfig():
        return {
            "GeckoDriver": {
                "program": {
                    "windows": "GeckoDriver/windows/geckodriver.exe",
                    "linux": "GeckoDriver/linux/geckodriver"
                },
                "run_sandboxed": {
                    "windows": False,
                    "linux": False
                }
            }
        }

    # Download
    def Download(force_downloads = False):
        if force_downloads or programs.ShouldProgramBeInstalled("GeckoDriver", "windows"):
            network.DownloadLatestGithubRelease(
                github_user = "mozilla",
                github_repo = "geckodriver",
                starts_with = "geckodriver",
                ends_with = "win32.zip",
                search_file = "geckodriver.exe",
                install_name = "GeckoDriver",
                install_dir = programs.GetProgramInstallDir("GeckoDriver", "windows"),
                install_files = ["geckodriver.exe"],
                verbose = config.default_flag_verbose,
                exit_on_failure = config.default_flag_exit_on_failure)
        if force_downloads or programs.ShouldProgramBeInstalled("GeckoDriver", "linux"):
            network.DownloadLatestGithubRelease(
                github_user = "mozilla",
                github_repo = "geckodriver",
                starts_with = "geckodriver",
                ends_with = "linux64.tar.gz",
                search_file = "geckodriver",
                install_name = "GeckoDriver",
                install_dir = programs.GetProgramInstallDir("GeckoDriver", "linux"),
                install_files = ["geckodriver"],
                verbose = config.default_flag_verbose,
                exit_on_failure = config.default_flag_exit_on_failure)
