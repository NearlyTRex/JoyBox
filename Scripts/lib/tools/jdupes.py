# Imports
import os, os.path
import sys

# Local imports
import config
import network
import programs
import toolbase

# Jdupes tool
class Jdupes(toolbase.ToolBase):

    # Get name
    def GetName(self):
        return "Jdupes"

    # Get config
    def GetConfig(self):
        return {
            "Jdupes": {
                "program": {
                    "windows": "Jdupes/windows/jdupes.exe",
                    "linux": "Jdupes/linux/jdupes"
                },
                "run_sandboxed": {
                    "windows": False,
                    "linux": False
                }
            }
        }

    # Download
    def Download(self, force_downloads = False, verbose = False, exit_on_failure = False):
        if force_downloads or programs.ShouldProgramBeInstalled("Jdupes", "windows"):
            network.DownloadLatestGithubRelease(
                github_user = "jbruchon",
                github_repo = "jdupes",
                starts_with = "jdupes",
                ends_with = "win64.zip",
                search_file = "jdupes.exe",
                install_name = "Jdupes",
                install_dir = programs.GetProgramInstallDir("Jdupes", "windows"),
                verbose = verbose,
                exit_on_failure = exit_on_failure)
        if force_downloads or programs.ShouldProgramBeInstalled("Jdupes", "linux"):
            network.DownloadLatestGithubRelease(
                github_user = "jbruchon",
                github_repo = "jdupes",
                starts_with = "jdupes",
                ends_with = "linux-x86_64.pkg.tar.xz",
                search_file = "jdupes",
                install_name = "Jdupes",
                install_dir = programs.GetProgramInstallDir("Jdupes", "linux"),
                verbose = verbose,
                exit_on_failure = exit_on_failure)