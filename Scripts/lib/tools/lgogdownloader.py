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
    def Setup(self, verbose = False, exit_on_failure = False):

        # Build linux program
        if programs.ShouldProgramBeInstalled("LGOGDownloader", "linux"):
            success = release.BuildAppImageFromSource(
                release_url = "https://github.com/NearlyTRex/LGOGDownloader.git",
                install_name = "LGOGDownloader",
                install_dir = programs.GetProgramInstallDir("LGOGDownloader", "linux"),
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
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup LGOGDownloader")

    # Configure
    def Configure(self, verbose = False, exit_on_failure = False):

        # Create config files
        if environment.IsLinuxPlatform():
            for config_filename, config_contents in config_files.items():
                success = system.TouchFile(
                    src = os.path.join(environment.GetToolsRootDir(), config_filename),
                    contents = config_contents.strip(),
                    verbose = verbose,
                    exit_on_failure = exit_on_failure)
                system.AssertCondition(success, "Could not setup LGOGDownloader config files")
