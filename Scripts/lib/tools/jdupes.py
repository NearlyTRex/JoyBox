# Imports
import os, os.path
import sys

# Local imports
import config
import system
import release
import programs
import toolbase

# Config files
config_files = {}

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

    # Setup
    def Setup(self, verbose = False, exit_on_failure = False):

        # Download windows program
        if programs.ShouldProgramBeInstalled("Jdupes", "windows"):
            success = release.DownloadGithubRelease(
                github_user = "NearlyTRex",
                github_repo = "JDupes",
                starts_with = "jdupes",
                ends_with = "win64.zip",
                search_file = "jdupes.exe",
                install_name = "Jdupes",
                install_dir = programs.GetProgramInstallDir("Jdupes", "windows"),
                release_type = config.release_type_archive,
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup Jdupes")

        # Download linux program
        if programs.ShouldProgramBeInstalled("Jdupes", "linux"):
            success = release.DownloadGithubRelease(
                github_user = "NearlyTRex",
                github_repo = "JDupes",
                starts_with = "jdupes",
                ends_with = "linux-x86_64.pkg.tar.xz",
                search_file = "jdupes",
                install_name = "Jdupes",
                install_dir = programs.GetProgramInstallDir("Jdupes", "linux"),
                release_type = config.release_type_archive,
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup Jdupes")
