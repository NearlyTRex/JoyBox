# Imports
import os, os.path
import sys

# Local imports
import config
import system
import environment
import release
import programs
import toolbase

# Config files
config_files = {}
config_files["LGOGDownloader/linux/LGOGDownloader.AppImage.home/.config/lgogdownloader/config.cfg"] = ""

# LGOGDownloader tool
class LGOGDownloader(toolbase.ToolBase):

    # Get name
    def GetName(self):
        return "LGOGDownloader"

    # Get config
    def GetConfig(self):
        return {
            "LGOGDownloader": {
                "program": {
                    "windows": None,
                    "linux": "LGOGDownloader/linux/LGOGDownloader.AppImage"
                },
                "run_sandboxed": {
                    "windows": False,
                    "linux": False
                }
            }
        }

    # Setup
    def Setup(self, verbose = False, pretend_run = False, exit_on_failure = False):

        # Build linux program
        if programs.ShouldProgramBeInstalled("LGOGDownloader", "linux"):
            success = release.BuildAppImageFromSource(
                release_url = "https://github.com/NearlyTRex/LGOGDownloader.git",
                output_file = "App-x86_64.AppImage",
                install_name = "LGOGDownloader",
                install_dir = programs.GetProgramInstallDir("LGOGDownloader", "linux"),
                backups_dir = programs.GetProgramBackupDir("LGOGDownloader", "linux"),
                build_cmd = [
                    "cmake", "..",
                    "&&",
                    "make", "-j", "4"
                ],
                build_dir = "Build",
                internal_copies = [
                    {"from": "Source/Build/lgogdownloader", "to": "AppImage/usr/bin/lgogdownloader"},
                    {"from": "AppImageTool/linux/app.desktop", "to": "AppImage/app.desktop"},
                    {"from": "AppImageTool/linux/icon.svg", "to": "AppImage/icon.svg"}
                ],
                internal_symlinks = [
                    {"from": "usr/bin/lgogdownloader", "to": "AppRun"}
                ],
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                system.LogError("Could not setup LGOGDownloader")
                return False
        return True

    # Setup offline
    def SetupOffline(self, verbose = False, pretend_run = False, exit_on_failure = False):

        # Setup linux program
        if programs.ShouldProgramBeInstalled("LGOGDownloader", "linux"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetProgramBackupDir("LGOGDownloader", "linux"),
                install_name = "LGOGDownloader",
                install_dir = programs.GetProgramInstallDir("LGOGDownloader", "linux"),
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                system.LogError("Could not setup LGOGDownloader")
                return False
        return True

    # Configure
    def Configure(self, verbose = False, pretend_run = False, exit_on_failure = False):

        # Create config files
        if environment.IsLinuxPlatform():
            for config_filename, config_contents in config_files.items():
                success = system.TouchFile(
                    src = system.JoinPaths(environment.GetToolsRootDir(), config_filename),
                    contents = config_contents.strip(),
                    verbose = verbose,
                    pretend_run = pretend_run,
                    exit_on_failure = exit_on_failure)
                if not success:
                    system.LogError("Could not setup LGOGDownloader config files")
                    return False
        return True
