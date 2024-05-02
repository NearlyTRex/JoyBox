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

# Picocrypt tool
class Picocrypt(toolbase.ToolBase):

    # Get name
    def GetName(self):
        return "Picocrypt"

    # Get config
    def GetConfig(self):
        return {
            "Picocrypt": {
                "program": {
                    "windows": "Picocrypt/windows/picocrypt.exe",
                    "linux": "Picocrypt/linux/picocrypt"
                },
                "run_sandboxed": {
                    "windows": False,
                    "linux": False
                }
            }
        }

    # Setup
    def Setup(self, verbose = False, exit_on_failure = False):

        # Build linux program
        if programs.ShouldProgramBeInstalled("Picocrypt", "linux"):
            success = release.BuildReleaseFromSource(
                release_url = "https://github.com/NearlyTRex/Picocrypt.git",
                output_file = "picocrypt",
                install_name = "Picocrypt",
                install_dir = programs.GetProgramInstallDir("Picocrypt", "linux"),
                backups_dir = programs.GetProgramBackupDir("Picocrypt", "linux"),
                build_dir = "cli/v2/picocrypt",
                build_cmd = [
                    "go", "build"
                ],
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup Picocrypt")

    # Setup offline
    def SetupOffline(self, verbose = False, exit_on_failure = False):

        # Setup linux program
        if programs.ShouldProgramBeInstalled("Picocrypt", "linux"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetProgramBackupDir("Picocrypt", "linux"),
                install_name = "Picocrypt",
                install_dir = programs.GetProgramInstallDir("Picocrypt", "linux"),
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup Picocrypt")
