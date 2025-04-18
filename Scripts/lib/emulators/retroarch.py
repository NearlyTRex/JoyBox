# Imports
import os
import os.path
import sys

# Local imports
import config
import environment
import system
import release
import programs
import hashing
import gui
import emulatorcommon
import emulatorbase

# Config files
config_files = {}
config_files["RetroArch/windows/retroarch.cfg"] = ""
config_files["RetroArch/linux/RetroArch-Linux-x86_64.AppImage.home/.config/retroarch/retroarch.cfg"] = ""

# System files
system_files = {}
system_files["system/panafz1.bin"] = "f47264dd47fe30f73ab3c010015c155b"
system_files["system/panafz10.bin"] = "51f2f43ae2f3508a14d9f56597e2d3ce"
system_files["system/panafz10-norsa.bin"] = "1477bda80dc33731a65468c1f5bcbee9"
system_files["system/panafz10e-anvil.bin"] = "a48e6746bd7edec0f40cff078f0bb19f"
system_files["system/panafz10e-anvil-norsa.bin"] = "cf11bbb5a16d7af9875cca9de9a15e09"
system_files["system/panafz1j.bin"] = "a496cfdded3da562759be3561317b605"
system_files["system/panafz1j-norsa.bin"] = "f6c71de7470d16abe4f71b1444883dc8"
system_files["system/goldstar.bin"] = "8639fd5e549bd6238cfee79e3e749114"
system_files["system/sanyotry.bin"] = "35fa1a1ebaaeea286dc5cd15487c13ea"
system_files["system/3do_arcade_saot.bin"] = "8970fc987ab89a7f64da9f8a8c4333ff"
system_files["system/sega_101.bin"] = "85ec9ca47d8f6807718151cbcca8b964"
system_files["system/mpr-17933.bin"] = "3240872c70984b6cbfda1586cab68dbe"
system_files["system/mpr-18811-mx.ic1"] = "255113ba943c92a54facd25a10fd780c"
system_files["system/mpr-19367-mx.ic1"] = "1cd19988d1d72a3e7caa0b73234c96b4"

# RetroArch emulator
class RetroArch(emulatorbase.EmulatorBase):

    # Get name
    def GetName(self):
        return "RetroArch"

    # Get platforms
    def GetPlatforms(self):
        return [
            config.Platform.OTHER_PANASONIC_3DO,
            config.Platform.OTHER_SEGA_SATURN
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
                    config.Platform.OTHER_PANASONIC_3DO: "opera/per_game"
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
                    config.Platform.OTHER_PANASONIC_3DO: "opera_libretro",
                    config.Platform.OTHER_SEGA_SATURN: "mednafen_saturn_libretro"
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
    def Setup(self, verbose = False, pretend_run = False, exit_on_failure = False):

        # Download windows program
        if programs.ShouldProgramBeInstalled("RetroArch", "windows"):
            success = release.DownloadGeneralRelease(
                archive_url = "https://buildbot.libretro.com/nightly/windows/x86_64/RetroArch.7z",
                search_file = "retroarch.exe",
                install_name = "RetroArch",
                install_dir = programs.GetProgramInstallDir("RetroArch", "windows"),
                backups_dir = programs.GetProgramBackupDir("RetroArch", "windows"),
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                system.LogError("Could not setup RetroArch")
                return False
            success = release.DownloadGeneralRelease(
                archive_url = "https://buildbot.libretro.com/nightly/windows/x86_64/RetroArch_cores.7z",
                search_file = "snes9x_libretro.dll",
                install_name = "RetroArch",
                install_dir = programs.GetEmulatorPathConfigValue("RetroArch", "cores_dir", "windows"),
                backups_dir = programs.GetProgramBackupDir("RetroArch", "windows"),
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                system.LogError("Could not setup RetroArch cores")
                return False

        # Download linux program
        if programs.ShouldProgramBeInstalled("RetroArch", "linux"):
            success = release.DownloadGeneralRelease(
                archive_url = "https://buildbot.libretro.com/nightly/linux/x86_64/RetroArch.7z",
                search_file = "RetroArch-Linux-x86_64.AppImage",
                install_name = "RetroArch",
                install_dir = programs.GetProgramInstallDir("RetroArch", "linux"),
                backups_dir = programs.GetProgramBackupDir("RetroArch", "linux"),
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                system.LogError("Could not setup RetroArch")
                return False
            success = release.DownloadGeneralRelease(
                archive_url = "https://buildbot.libretro.com/nightly/linux/x86_64/RetroArch_cores.7z",
                search_file = "snes9x_libretro.so",
                install_name = "RetroArch",
                install_dir = programs.GetEmulatorPathConfigValue("RetroArch", "cores_dir", "linux"),
                backups_dir = programs.GetProgramBackupDir("RetroArch", "linux"),
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                system.LogError("Could not setup RetroArch cores")
                return False
        return True

    # Setup offline
    def SetupOffline(self, verbose = False, pretend_run = False, exit_on_failure = False):

        # Setup windows program
        if programs.ShouldProgramBeInstalled("RetroArch", "windows"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetProgramBackupDir("RetroArch", "windows"),
                install_name = "RetroArch",
                install_dir = programs.GetProgramInstallDir("RetroArch", "windows"),
                preferred_archive = "RetroArch.7z",
                search_file = "retroarch.exe",
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                system.LogError("Could not setup RetroArch")
                return False
            success = release.SetupStoredRelease(
                archive_dir = programs.GetProgramBackupDir("RetroArch", "windows"),
                install_name = "RetroArch",
                install_dir = programs.GetEmulatorPathConfigValue("RetroArch", "cores_dir", "windows"),
                preferred_archive = "RetroArch_cores.7z",
                search_file = "snes9x_libretro.dll",
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                system.LogError("Could not setup RetroArch cores")
                return False

        # Setup linux program
        if programs.ShouldProgramBeInstalled("RetroArch", "linux"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetProgramBackupDir("RetroArch", "linux"),
                install_name = "RetroArch",
                install_dir = programs.GetProgramInstallDir("RetroArch", "linux"),
                preferred_archive = "RetroArch.7z",
                search_file = "RetroArch-Linux-x86_64.AppImage",
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                system.LogError("Could not setup RetroArch")
                return False
            success = release.SetupStoredRelease(
                archive_dir = programs.GetProgramBackupDir("RetroArch", "linux"),
                install_name = "RetroArch",
                install_dir = programs.GetEmulatorPathConfigValue("RetroArch", "cores_dir", "linux"),
                preferred_archive = "RetroArch_cores.7z",
                search_file = "snes9x_libretro.so",
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                system.LogError("Could not setup RetroArch cores")
                return False
        return True

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
            if not success:
                system.LogError("Could not setup RetroArch config files")
                return False

        # Verify system files
        for filename, expected_md5 in system_files.items():
            actual_md5 = hashing.CalculateFileMD5(
                src = system.JoinPaths(environment.GetLockerGamingEmulatorSetupDir("RetroArch"), filename),
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            success = (expected_md5 == actual_md5)
            if not success:
                system.LogError("Could not verify RetroArch system file %s" % filename)
                return False

        # Copy system files
        for filename in system_files.keys():
            for platform in ["windows", "linux"]:
                success = system.SmartCopy(
                    src = system.JoinPaths(environment.GetLockerGamingEmulatorSetupDir("RetroArch"), filename),
                    dest = system.JoinPaths(programs.GetEmulatorPathConfigValue("RetroArch", "setup_dir", platform), filename),
                    verbose = verbose,
                    pretend_run = pretend_run,
                    exit_on_failure = exit_on_failure)
                if not success:
                    system.LogError("Could not setup RetroArch system files")
                    return False
        return True

    # Launch
    def Launch(
        self,
        game_info,
        capture_type = None,
        capture_file = None,
        fullscreen = False,
        verbose = False,
        pretend_run = False,
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
        core_file = system.JoinPaths(cores_dir, cores_mapping[game_platform] + cores_ext)
        if not os.path.exists(core_file):
            gui.DisplayErrorPopup(
                title_text = "RetroArch core not found",
                message_text = "RetroArch core '%s' could not be found!" % cores_mapping[game_platform])

        # Get launch command
        launch_cmd = [
            programs.GetEmulatorProgram("RetroArch"),
            "-L", system.JoinPaths(cores_dir, cores_mapping[game_platform] + cores_ext),
            config.token_game_file
        ]
        if fullscreen:
            launch_cmd += [
                "-f"
            ]

        # Launch game
        return emulatorcommon.SimpleLaunch(
            game_info = game_info,
            launch_cmd = launch_cmd,
            capture_type = capture_type,
            capture_file = capture_file,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
