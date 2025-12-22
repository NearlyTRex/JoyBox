# Imports
import os, os.path
import sys

# Local imports
import config
import system
import logger
import paths
import environment
import fileops
import release
import programs
import toolbase

# Config files
config_files = {}
config_files["LGOGDownloader/linux/LGOGDownloader.AppImage.home/.config/lgogdownloader/config.cfg"] = ""

# LGOGDownloader tool
class LGOGDownloader(toolbase.ToolBase):

    # Get name
    def get_name(self):
        return "LGOGDownloader"

    # Get config
    def get_config(self):
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
    def setup(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

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
                locker_type = setup_params.locker_type,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup LGOGDownloader")
                return False
        return True

    # Setup offline
    def setup_offline(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Setup linux program
        if programs.ShouldProgramBeInstalled("LGOGDownloader", "linux"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetProgramBackupDir("LGOGDownloader", "linux"),
                install_name = "LGOGDownloader",
                install_dir = programs.GetProgramInstallDir("LGOGDownloader", "linux"),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup LGOGDownloader")
                return False
        return True

    # Configure
    def configure(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Create config files
        if environment.is_linux_platform():
            for config_filename, config_contents in config_files.items():
                success = fileops.touch_file(
                    src = paths.join_paths(environment.get_tools_root_dir(), config_filename),
                    contents = config_contents.strip(),
                    verbose = setup_params.verbose,
                    pretend_run = setup_params.pretend_run,
                    exit_on_failure = setup_params.exit_on_failure)
                if not success:
                    logger.log_error("Could not setup LGOGDownloader config files")
                    return False
        return True
