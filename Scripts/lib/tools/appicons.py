# Imports
import os, os.path
import sys

# Local imports
import system
import network
import programs
import toolbase

# Config files
config_files = {}

# AppIcons tool
class AppIcons(toolbase.ToolBase):

    # Get name
    def GetName(self):
        return "AppIcons"

    # Get config
    def GetConfig(self):
        return {
        }

    # Setup
    def Setup(self, verbose = False, exit_on_failure = False):

        # Download library
        if programs.ShouldLibraryBeInstalled("AppIcons"):
            success = network.DownloadGithubRepository(
                github_user = "NearlyTRex",
                github_repo = "BostonIcons",
                output_dir = programs.GetLibraryInstallDir("AppIcons"),
                clean = True,
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not download AppIcons")
