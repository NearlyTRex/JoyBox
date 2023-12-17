# Imports
import os, os.path
import sys

# Local imports
import config
import network
import programs
import toolbase

# Config file
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

    # Download
    def Download(self, force_downloads = False, verbose = False, exit_on_failure = False):
        if force_downloads or programs.ShouldProgramBeInstalled("LGOGDownloader", "linux"):
            network.BuildAppImageFromSource(
                release_url = "https://github.com/NearlyTRex/LGOGDownloader.git",
                output_name = "LGOGDownloader",
                output_dir = programs.GetProgramInstallDir("LGOGDownloader", "linux"),
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

    # Setup
    def Setup(self, verbose = False, exit_on_failure = False):

        # Create config files
        for config_filename, config_contents in config_files.items():
            system.TouchFile(
                src = os.path.join(environment.GetToolsRootDir(), config_filename),
                contents = config_contents.strip(),
                verbose = verbose,
                exit_on_failure = exit_on_failure)