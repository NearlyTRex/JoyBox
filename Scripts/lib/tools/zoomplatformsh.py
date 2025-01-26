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

# ZoomPlatformSH tool
class ZoomPlatformSH(toolbase.ToolBase):

    # Get name
    def GetName(self):
        return "ZoomPlatformSH"

    # Get config
    def GetConfig(self):
        return {
            "ZoomPlatformSH": {
                "program": "ZoomPlatformSH/lib/zoom-platform.sh"
            }
        }

    # Setup
    def Setup(self, verbose = False, pretend_run = False, exit_on_failure = False):

        # Download library
        if programs.ShouldLibraryBeInstalled("ZoomPlatformSH"):
            success = release.DownloadGithubRelease(
                github_user = "ZOOM-Platform",
                github_repo = "zoom-platform.sh",
                starts_with = "zoom-platform",
                ends_with = ".sh",
                search_file = "zoom-platform.sh",
                install_name = "ZoomPlatformSH",
                install_dir = programs.GetLibraryInstallDir("ZoomPlatformSH", "lib"),
                backups_dir = programs.GetLibraryBackupDir("ZoomPlatformSH", "lib"),
                install_files = ["zoom-platform.sh"],
                release_type = config.ReleaseType.PROGRAM,
                chmod_files = [
                    {
                        "file": "zoom-platform.sh",
                        "perms": 755
                    }
                ],
                get_latest = True,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                system.LogError("Could not setup ZoomPlatformSH")
                return False
        return True

    # Setup offline
    def SetupOffline(self, verbose = False, pretend_run = False, exit_on_failure = False):

        # Setup library
        if programs.ShouldLibraryBeInstalled("ZoomPlatformSH"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetLibraryBackupDir("ZoomPlatformSH", "lib"),
                install_name = "ZoomPlatformSH",
                install_dir = programs.GetLibraryInstallDir("ZoomPlatformSH", "lib"),
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                system.LogError("Could not setup ZoomPlatformSH")
                return False
        return True
