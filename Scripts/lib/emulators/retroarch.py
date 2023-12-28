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
import gui
import emulatorcommon
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
            config.game_subcategory_panasonic_3do,
            config.game_subcategory_sega_saturn
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
                    config.game_subcategory_panasonic_3do: "opera/per_game"
                },
                "setup_dir": {
                    "windows": "RetroArch/windows",
                    "linux": "RetroArch/linux/RetroArch-Linux-x86_64.AppImage.home/.config/retroarch"
                },
                "setup_files": [

                    # Panasonic 3DO
                    {
                        "file": "system/panafz1.bin",
                        "md5": "f47264dd47fe30f73ab3c010015c155b"
                    },
                    {
                        "file": "system/panafz10.bin",
                        "md5": "51f2f43ae2f3508a14d9f56597e2d3ce"
                    },
                    {
                        "file": "system/panafz10-norsa.bin",
                        "md5": "1477bda80dc33731a65468c1f5bcbee9"
                    },
                    {
                        "file": "system/panafz10e-anvil.bin",
                        "md5": "a48e6746bd7edec0f40cff078f0bb19f"
                    },
                    {
                        "file": "system/panafz10e-anvil-norsa.bin",
                        "md5": "cf11bbb5a16d7af9875cca9de9a15e09"
                    },
                    {
                        "file": "system/panafz1j.bin",
                        "md5": "a496cfdded3da562759be3561317b605"
                    },
                    {
                        "file": "system/panafz1j-norsa.bin",
                        "md5": "f6c71de7470d16abe4f71b1444883dc8"
                    },
                    {
                        "file": "system/goldstar.bin",
                        "md5": "8639fd5e549bd6238cfee79e3e749114"
                    },
                    {
                        "file": "system/sanyotry.bin",
                        "md5": "35fa1a1ebaaeea286dc5cd15487c13ea"
                    },
                    {
                        "file": "system/3do_arcade_saot.bin",
                        "md5": "8970fc987ab89a7f64da9f8a8c4333ff"
                    },

                    # Sega Saturn
                    {
                        "file": "system/sega_101.bin",
                        "md5": "85ec9ca47d8f6807718151cbcca8b964"
                    },
                    {
                        "file": "system/mpr-17933.bin",
                        "md5": "3240872c70984b6cbfda1586cab68dbe"
                    },
                    {
                        "file": "system/mpr-18811-mx.ic1",
                        "md5": "255113ba943c92a54facd25a10fd780c"
                    },
                    {
                        "file": "system/mpr-19367-mx.ic1",
                        "md5": "1cd19988d1d72a3e7caa0b73234c96b4"
                    }
                ],
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
                    config.game_subcategory_panasonic_3do: "opera_libretro",
                    config.game_subcategory_sega_saturn: "mednafen_saturn_libretro"
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

    # Setup
    def Setup(self, verbose = False, exit_on_failure = False):

        # Download windows program
        if programs.ShouldProgramBeInstalled("RetroArch", "windows"):
            success = network.DownloadGeneralRelease(
                archive_url = "https://buildbot.libretro.com/nightly/windows/x86_64/RetroArch.7z",
                search_file = "retroarch.exe",
                install_name = "RetroArch",
                install_dir = programs.GetProgramInstallDir("RetroArch", "windows"),
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup RetroArch")
            success = network.DownloadGeneralRelease(
                archive_url = "https://buildbot.libretro.com/nightly/windows/x86_64/RetroArch_cores.7z",
                search_file = "snes9x_libretro.dll",
                install_name = "RetroArch",
                install_dir = programs.GetEmulatorPathConfigValue("RetroArch", "cores_dir", "windows"),
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup RetroArch cores")

        # Download linux program
        if programs.ShouldProgramBeInstalled("RetroArch", "linux"):
            success = network.DownloadGeneralRelease(
                archive_url = "https://buildbot.libretro.com/nightly/linux/x86_64/RetroArch.7z",
                search_file = "RetroArch-Linux-x86_64.AppImage",
                install_name = "RetroArch",
                install_dir = programs.GetProgramInstallDir("RetroArch", "linux"),
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup RetroArch")
            success = network.DownloadGeneralRelease(
                archive_url = "https://buildbot.libretro.com/nightly/linux/x86_64/RetroArch_cores.7z",
                search_file = "snes9x_libretro.so",
                install_name = "RetroArch",
                install_dir = programs.GetEmulatorPathConfigValue("RetroArch", "cores_dir", "linux"),
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup RetroArch cores")

        # Create config files
        for config_filename, config_contents in config_files.items():
            success = system.TouchFile(
                src = os.path.join(environment.GetEmulatorsRootDir(), config_filename),
                contents = config_contents.strip(),
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup RetroArch config files")

        # Copy setup files
        for platform in ["windows", "linux"]:
            success = system.CopyContents(
                src = environment.GetSyncedGameEmulatorSetupDir("RetroArch"),
                dest = programs.GetEmulatorPathConfigValue("RetroArch", "setup_dir", platform),
                skip_existing = True,
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup RetroArch system files")

    # Launch
    def Launch(
        self,
        game_info,
        capture_type,
        fullscreen = False,
        verbose = False,
        exit_on_failure = False):

        # Get game info
        game_platform = game_info.get_platform()

        # Get core info
        cores_dir = programs.GetEmulatorPathConfigValue("RetroArch", "cores_dir")
        cores_ext = programs.GetEmulatorConfigValue("RetroArch", "cores_ext")
        cores_mapping = programs.GetEmulatorConfigValue("RetroArch", "cores_mapping")

        # Check if this platform is valid
        if not game_platform in cores_mapping:
            gui.DisplayErrorPopup(
                title_text = "Launch platform not defined",
                message_text = "Launch platform %s not defined in RetroArch config" % game_platform)

        # Check if core is installed
        core_file = os.path.join(cores_dir, cores_mapping[game_platform] + cores_ext)
        if not os.path.exists(core_file):
            gui.DisplayErrorPopup(
                title_text = "RetroArch core not found",
                message_text = "RetroArch core '%s' could not be found!" % cores_mapping[game_platform])

        # Get launch command
        launch_cmd = [
            programs.GetEmulatorProgram("RetroArch"),
            "-L", os.path.join(cores_dir, cores_mapping[game_platform] + cores_ext),
            config.token_game_file
        ]
        if fullscreen:
            launch_cmd += [
                "-f"
            ]

        # Launch game
        emulatorcommon.SimpleLaunch(
            game_info = game_info,
            launch_cmd = launch_cmd,
            capture_type = capture_type,
            verbose = verbose,
            exit_on_failure = exit_on_failure)
