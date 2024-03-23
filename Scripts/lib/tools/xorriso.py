# Imports
import os, os.path
import sys

# Local imports
import config
import system
import network
import release
import programs
import toolbase

# Config files
config_files = {}

# XorrISO tool
class XorrISO(toolbase.ToolBase):

    # Get name
    def GetName(self):
        return "XorrISO"

    # Get config
    def GetConfig(self):
        return {
            "XorrISO": {
                "program": {
                    "windows": "XorrISO/windows/xorriso.exe",
                    "linux": "XorrISO/linux/XorrISO.AppImage"
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
        if programs.ShouldProgramBeInstalled("XorrISO", "windows"):
            success = network.DownloadGithubRepository(
                github_user = "PeyTy",
                github_repo = "xorriso-exe-for-windows",
                output_dir = programs.GetProgramInstallDir("XorrISO", "windows"),
                clean = True,
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup XorrISO")

        # Build linux program
        if programs.ShouldProgramBeInstalled("XorrISO", "linux"):
            success = release.BuildAppImageFromSource(
                release_url = "https://www.gnu.org/software/xorriso/xorriso-1.5.6.pl02.tar.gz",
                install_name = "XorrISO",
                install_dir = programs.GetProgramInstallDir("XorrISO", "linux"),
                build_cmd = [
                    "cd", "xorriso-1.5.6",
                    "./bootstrap",
                    "&&",
                    "./configure",
                    "&&",
                    "make", "-j", "4"
                ],
                internal_copies = [
                    {"from": "Source/xorriso-1.5.6/xorriso/xorriso", "to": "AppImage/usr/bin/xorriso"},
                    {"from": "AppImageTool/linux/app.desktop", "to": "AppImage/app.desktop"},
                    {"from": "AppImageTool/linux/icon.svg", "to": "AppImage/icon.svg"}
                ],
                internal_symlinks = [
                    {"from": "usr/bin/xorriso", "to": "AppRun"}
                ],
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup XorrISO")
