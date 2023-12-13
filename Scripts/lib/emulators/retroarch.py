# Imports
import os
import os.path
import sys

# Local imports
import config
import environment
import system
import network
import programs
import launchcommon
import gui
import emulatorbase

# Config files
config_files = {}
config_files["RetroArch/windows/retroarch.cfg"] = ""
config_files["RetroArch/linux/RetroArch-Linux-x86_64.AppImage.home/.config/retroarch/retroarch.cfg"] = ""

# RetroArch emulator
class RetroArch(emulatorbase.EmulatorBase):

    # Get name
    def GetName(self):
        return "RetroArch"

    # Get platforms
    def GetPlatforms(self):
        return [
            "Panasonic 3DO",
            "Sega Saturn"
        ]

    # Get config
    def GetConfig(self):
        return {
            "RetroArch": {
                "program": {
                    "windows": "RetroArch/windows/retroarch.exe",
                    "linux": "RetroArch/linux/RetroArch-Linux-x86_64.AppImage"
                },
                "save_dir": {
                    "windows": "RetroArch/windows/saves",
                    "linux": "RetroArch/linux/RetroArch-Linux-x86_64.AppImage.home/.config/retroarch/saves"
                },
                "save_base_dir": {
                    "windows": "RetroArch/windows/saves",
                    "linux": "RetroArch/linux/RetroArch-Linux-x86_64.AppImage.home/.config/retroarch/saves"
                },
                "save_sub_dirs": {

                    # Other
                    "Panasonic 3DO": "opera/per_game"
                },
                "setup_dir": {
                    "windows": "RetroArch/windows",
                    "linux": "RetroArch/linux/RetroArch-Linux-x86_64.AppImage.home/.config/retroarch"
                },
                "cores_dir": {
                    "windows": "RetroArch/windows/cores",
                    "linux": "RetroArch/linux/RetroArch-Linux-x86_64.AppImage.home/.config/retroarch/cores"
                },
                "cores_ext": {
                    "windows": ".dll",
                    "linux": ".so"
                },
                "cores_mapping": {

                    # Other
                    "Panasonic 3DO": "opera_libretro",
                    "Sega Saturn": "mednafen_saturn_libretro"
                },
                "config_file": {
                    "windows": "RetroArch/windows/retroarch.cfg",
                    "linux": "RetroArch/linux/RetroArch-Linux-x86_64.AppImage.home/.config/retroarch/retroarch.cfg"
                },
                "run_sandboxed": {
                    "windows": False,
                    "linux": False
                }
            }
        }

    # Download
    def Download(self, force_downloads = False, verbose = False, exit_on_failure = False):
        if force_downloads or programs.ShouldProgramBeInstalled("RetroArch", "windows"):
            network.DownloadGeneralRelease(
                archive_url = "https://buildbot.libretro.com/nightly/windows/x86_64/RetroArch.7z",
                search_file = "retroarch.exe",
                install_name = "RetroArch",
                install_dir = programs.GetProgramInstallDir("RetroArch", "windows"),
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            network.DownloadGeneralRelease(
                archive_url = "https://buildbot.libretro.com/nightly/windows/x86_64/RetroArch_cores.7z",
                search_file = "snes9x_libretro.dll",
                install_name = "RetroArch",
                install_dir = programs.GetEmulatorPathConfigValue("RetroArch", "cores_dir", "windows"),
                verbose = verbose,
                exit_on_failure = exit_on_failure)
        if force_downloads or programs.ShouldProgramBeInstalled("RetroArch", "linux"):
            network.DownloadGeneralRelease(
                archive_url = "https://buildbot.libretro.com/nightly/linux/x86_64/RetroArch.7z",
                search_file = "RetroArch-Linux-x86_64.AppImage",
                install_name = "RetroArch",
                install_dir = programs.GetProgramInstallDir("RetroArch", "linux"),
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            network.DownloadGeneralRelease(
                archive_url = "https://buildbot.libretro.com/nightly/linux/x86_64/RetroArch_cores.7z",
                search_file = "snes9x_libretro.so",
                install_name = "RetroArch",
                install_dir = programs.GetEmulatorPathConfigValue("RetroArch", "cores_dir", "linux"),
                verbose = verbose,
                exit_on_failure = exit_on_failure)

    # Setup
    def Setup(self, verbose = False, exit_on_failure = False):

        # Create config files
        for config_filename, config_contents in config_files.items():
            system.TouchFile(
                src = os.path.join(environment.GetEmulatorsRootDir(), config_filename),
                contents = config_contents,
                verbose = verbose,
                exit_on_failure = exit_on_failure)

        # Copy setup files
        for platform in ["windows", "linux"]:
            system.CopyContents(
                src = environment.GetSyncedGameEmulatorSetupDir("RetroArch"),
                dest = programs.GetEmulatorPathConfigValue("RetroArch", "setup_dir", platform),
                skip_existing = True,
                verbose = verbose,
                exit_on_failure = exit_on_failure)

    # Launch
    def Launch(
        self,
        launch_name,
        launch_platform,
        launch_file,
        launch_artwork,
        launch_save_dir,
        launch_general_save_dir,
        launch_capture_type,
        fullscreen = False,
        verbose = False,
        exit_on_failure = False):

        # Get core info
        cores_dir = programs.GetEmulatorPathConfigValue("RetroArch", "cores_dir")
        cores_ext = programs.GetEmulatorConfigValue("RetroArch", "cores_ext")
        cores_mapping = programs.GetEmulatorConfigValue("RetroArch", "cores_mapping")

        # Check if this platform is valid
        if not launch_platform in cores_mapping:
            gui.DisplayErrorPopup(
                title_text = "Launch platform not defined",
                message_text = "Launch platform %s not defined in RetroArch config" % launch_platform)

        # Check if core is installed
        core_file = os.path.join(cores_dir, cores_mapping[launch_platform] + cores_ext)
        if not os.path.exists(core_file):
            gui.DisplayErrorPopup(
                title_text = "RetroArch core not found",
                message_text = "RetroArch core '%s' could not be found!" % cores_mapping[launch_platform])

        # Get launch command
        launch_cmd = [
            programs.GetEmulatorProgram("RetroArch"),
            "-L", os.path.join(cores_dir, cores_mapping[launch_platform] + cores_ext),
            config.token_game_file
        ]
        if fullscreen:
            launch_cmd += [
                "-f"
            ]

        # Launch game
        launchcommon.SimpleLaunch(
            launch_cmd = launch_cmd,
            launch_name = launch_name,
            launch_platform = launch_platform,
            launch_file = launch_file,
            launch_artwork = launch_artwork,
            launch_save_dir = launch_save_dir,
            launch_capture_type = launch_capture_type,
            verbose = verbose,
            exit_on_failure = exit_on_failure)
