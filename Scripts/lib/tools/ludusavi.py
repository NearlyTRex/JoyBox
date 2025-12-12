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
    def Setup(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

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
                backups_dir = programs.GetProgramBackupDir("Ludusavi", "windows"),
                install_files = ["ludusavi.exe"],
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                system.LogError("Could not setup Ludusavi")
                return False

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
                backups_dir = programs.GetProgramBackupDir("Ludusavi", "linux"),
                install_files = ["ludusavi"],
                chmod_files = [
                    {
                        "file": "ludusavi",
                        "perms": 755
                    }
                ],
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                system.LogError("Could not setup Ludusavi")
                return False
        return True

    # Setup offline
    def SetupOffline(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Setup windows program
        if programs.ShouldProgramBeInstalled("Ludusavi", "windows"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetProgramBackupDir("Ludusavi", "windows"),
                install_name = "Ludusavi",
                install_dir = programs.GetProgramInstallDir("Ludusavi", "windows"),
                search_file = "ludusavi.exe",
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                system.LogError("Could not setup Ludusavi")
                return False

        # Setup linux program
        if programs.ShouldProgramBeInstalled("Ludusavi", "linux"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetProgramBackupDir("Ludusavi", "linux"),
                install_name = "Ludusavi",
                install_dir = programs.GetProgramInstallDir("Ludusavi", "linux"),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                system.LogError("Could not setup Ludusavi")
                return False
        return True

    # Configure
    def Configure(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Create config files
        for config_filename, config_contents in config_files.items():
            success = system.TouchFile(
                src = system.JoinPaths(environment.GetToolsRootDir(), config_filename),
                contents = config_contents.strip(),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                system.LogError("Could not setup Ludusavi config files")
                return False
        return True
