# Imports
import os, os.path
import sys

# Local imports
import config
import system
import release
import programs
import environment
import toolbase

# Config files
config_files = {}
config_files["Ludusavi/windows/ludusavi.portable"] = ""
config_files["Ludusavi/windows/config.yaml"] = """
---
runtime:
  threads: ~
manifest:
  url: "https://raw.githubusercontent.com/mtkennerly/ludusavi-manifest/master/data/manifest.yaml"
language: en-US
theme: light
roots: []
redirects: []
backup:
  path: .\\ludusavi-backup
restore:
  path: .\\ludusavi-backup
scan:
  showDeselectedGames: true
  showUnchangedGames: true
  showUnscannedGames: true
cloud:
  remote: ~
  path: ludusavi-backup
  synchronize: true
customGames: []
"""
config_files["Ludusavi/linux/ludusavi.portable"] = ""
config_files["Ludusavi/linux/config.yaml"] = """
---
runtime:
  threads: ~
manifest:
  url: "https://raw.githubusercontent.com/mtkennerly/ludusavi-manifest/master/data/manifest.yaml"
language: en-US
theme: light
roots: []
redirects: []
backup:
  path: ./ludusavi-backup
restore:
  path: ./ludusavi-backup
scan:
  showDeselectedGames: true
  showUnchangedGames: true
  showUnscannedGames: true
cloud:
  remote: ~
  path: ludusavi-backup
  synchronize: true
customGames: []
"""

# Ludusavi tool
class Ludusavi(toolbase.ToolBase):

    # Get name
    def GetName(self):
        return "Ludusavi"

    # Get config
    def GetConfig(self):
        return {
            "Ludusavi": {
                "program": {
                    "windows": "Ludusavi/windows/ludusavi.exe",
                    "linux": "Ludusavi/linux/ludusavi"
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
        if programs.ShouldProgramBeInstalled("Ludusavi", "windows"):
            success = release.DownloadGithubRelease(
                github_user = "mtkennerly",
                github_repo = "ludusavi",
                starts_with = "ludusavi",
                ends_with = "win64.zip",
                search_file = "ludusavi.exe",
                install_name = "Ludusavi",
                install_dir = programs.GetProgramInstallDir("Ludusavi", "windows"),
                install_files = ["ludusavi.exe"],
                release_type = config.release_type_archive,
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup Ludusavi")

        # Download linux program
        if programs.ShouldProgramBeInstalled("Ludusavi", "linux"):
            success = release.DownloadGithubRelease(
                github_user = "mtkennerly",
                github_repo = "ludusavi",
                starts_with = "ludusavi",
                ends_with = "linux.zip",
                search_file = "ludusavi",
                install_name = "Ludusavi",
                install_dir = programs.GetProgramInstallDir("Ludusavi", "linux"),
                install_files = ["ludusavi"],
                release_type = config.release_type_archive,
                chmod_files = [
                    {
                        "file": "ludusavi",
                        "perms": 755
                    }
                ],
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup Ludusavi")

    # Configure
    def Configure(self, verbose = False, exit_on_failure = False):

        # Create config files
        for config_filename, config_contents in config_files.items():
            success = system.TouchFile(
                src = os.path.join(environment.GetToolsRootDir(), config_filename),
                contents = config_contents.strip(),
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup Ludusavi config files")
