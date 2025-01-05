# Imports
import os, os.path
import sys

# Local imports
import config
import environment
import system
import release
import programs
import emulatorbase

# Config files
config_files = {}
config_files["Ryujinx/windows/portable/Config.json"] = ""
config_files["Ryujinx/linux/portable/Config.json"] = ""

# System files
system_files = {}

# Ryujinx emulator
class Ryujinx(emulatorbase.EmulatorBase):

    # Get name
    def GetName(self):
        return "Ryujinx"

    # Get platforms
    def GetPlatforms(self):
        return []

    # Get config
    def GetConfig(self):
        return {
            "Ryujinx": {
                "program": {
                    "windows": "Ryujinx/windows/Ryujinx.exe",
                    "linux": "Ryujinx/linux/Ryujinx"
                },
                "run_sandboxed": {
                    "windows": False,
                    "linux": False
                }
            }
        }

    # Setup
    def Setup(self, verbose = False, pretend_run = False, exit_on_failure = False):

        # Download windows program
        if programs.ShouldProgramBeInstalled("Ryujinx", "windows"):
            success = release.DownloadGithubRelease(
                github_user = "Ryujinx",
                github_repo = "release-channel-master",
                starts_with = "ryujinx",
                ends_with = "win_x64.zip",
                search_file = "Ryujinx.exe",
                install_name = "Ryujinx",
                install_dir = programs.GetProgramInstallDir("Ryujinx", "windows"),
                backups_dir = programs.GetProgramBackupDir("Ryujinx", "windows"),
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup Ryujinx")

        # Download linux program
        if programs.ShouldProgramBeInstalled("Ryujinx", "linux"):
            success = release.DownloadGithubRelease(
                github_user = "Ryujinx",
                github_repo = "release-channel-master",
                starts_with = "ryujinx",
                ends_with = "linux_x64.tar.gz",
                search_file = "Ryujinx.sh",
                install_name = "Ryujinx",
                install_dir = programs.GetProgramInstallDir("Ryujinx", "linux"),
                backups_dir = programs.GetProgramBackupDir("Ryujinx", "linux"),
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup Ryujinx")

    # Setup offline
    def SetupOffline(self, verbose = False, pretend_run = False, exit_on_failure = False):

        # Setup windows program
        if programs.ShouldProgramBeInstalled("Ryujinx", "windows"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetProgramBackupDir("Ryujinx", "windows"),
                install_name = "Ryujinx",
                install_dir = programs.GetProgramInstallDir("Ryujinx", "windows"),
                search_file = "Ryujinx.exe",
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup Ryujinx")

        # Setup linux program
        if programs.ShouldProgramBeInstalled("Ryujinx", "linux"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetProgramBackupDir("Ryujinx", "linux"),
                install_name = "Ryujinx",
                install_dir = programs.GetProgramInstallDir("Ryujinx", "linux"),
                search_file = "Ryujinx.sh",
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup Ryujinx")

    # Configure
    def Configure(self, verbose = False, pretend_run = False, exit_on_failure = False):

        # Create config files
        for config_filename, config_contents in config_files.items():
            success = system.TouchFile(
                src = system.JoinPaths(environment.GetEmulatorsRootDir(), config_filename),
                contents = config_contents.strip(),
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup Ryujinx config files")
