# Imports
import os, os.path
import sys

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.append(lib_folder)
import config
import system
import network
import programs
import environment

# Local imports
from . import base

# Config file
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
class Ludusavi(base.ToolBase):

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

    # Download
    def Download(self, force_downloads = False, verbose = False, exit_on_failure = False):
        if force_downloads or programs.ShouldProgramBeInstalled("Ludusavi", "windows"):
            network.DownloadLatestGithubRelease(
                github_user = "mtkennerly",
                github_repo = "ludusavi",
                starts_with = "ludusavi",
                ends_with = "win64.zip",
                search_file = "ludusavi.exe",
                install_name = "Ludusavi",
                install_dir = programs.GetProgramInstallDir("Ludusavi", "windows"),
                install_files = ["ludusavi.exe"],
                verbose = verbose,
                exit_on_failure = exit_on_failure)
        if force_downloads or programs.ShouldProgramBeInstalled("Ludusavi", "linux"):
            network.DownloadLatestGithubRelease(
                github_user = "mtkennerly",
                github_repo = "ludusavi",
                starts_with = "ludusavi",
                ends_with = "linux.zip",
                search_file = "ludusavi",
                install_name = "Ludusavi",
                install_dir = programs.GetProgramInstallDir("Ludusavi", "linux"),
                install_files = ["ludusavi"],
                chmod_files = [
                    {
                        "file": "ludusavi",
                        "perms": 755
                    }
                ],
                verbose = verbose,
                exit_on_failure = exit_on_failure)

    # Setup
    def Setup(self, verbose = False, exit_on_failure = False):

        # Create config files
        for config_filename, config_contents in config_files.items():
            system.TouchFile(
                src = os.path.join(environment.GetToolsRootDir(), config_filename),
                contents = config_contents,
                verbose = verbose,
                exit_on_failure = exit_on_failure)
