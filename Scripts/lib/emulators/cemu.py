# Imports
import os, os.path
import sys

# Local imports
import config
import environment
import system
import release
import programs
import nintendo
import gui
import emulatorcommon
import emulatorbase

# Config files
config_files = {}
config_files["Cemu/windows/settings.xml"] = ""
config_files["Cemu/windows/keys.txt"] = ""
config_files["Cemu/linux/Cemu.AppImage.home/.config/Cemu/settings.xml"] = ""
config_files["Cemu/linux/Cemu.AppImage.home/.local/share/Cemu/keys.txt"] = ""

# System files
system_files = {}

# Cemu emulator
class Cemu(emulatorbase.EmulatorBase):

    # Get name
    def GetName(self):
        return "Cemu"

    # Get platforms
    def GetPlatforms(self):
        return [
            config.Platform.NINTENDO_WII_U,
            config.Platform.NINTENDO_WII_U_ESHOP
        ]

    # Get config
    def GetConfig(self):
        return {
            "Cemu": {
                "program": {
                    "windows": "Cemu/windows/Cemu.exe",
                    "linux": "Cemu/linux/Cemu.AppImage"
                },
                "save_dir": {
                    "windows": "Cemu/windows/mlc01/usr/save/00050000",
                    "linux": "Cemu/linux/Cemu.AppImage.home/.local/share/Cemu/mlc01/usr/save/00050000"
                },
                "setup_dir": {
                    "windows": "Cemu/windows",
                    "linux": "Cemu/linux/Cemu.AppImage.home/.local/share/Cemu"
                },
                "config_file": {
                    "windows": "Cemu/windows/settings.xml",
                    "linux": "Cemu/linux/Cemu.AppImage.home/.config/Cemu/settings.xml"
                },
                "keys_file": {
                    "windows": "Cemu/windows/keys.txt",
                    "linux": "Cemu/linux/Cemu.AppImage.home/.local/share/Cemu/keys.txt"
                },
                "run_sandboxed": {
                    "windows": False,
                    "linux": False
                }
            }
        }

    # Install add-ons
    def InstallAddons(self, dlc_dirs = [], update_dirs = [], verbose = False, pretend_run = False, exit_on_failure = False):
        for package_dirset in [dlc_dirs, update_dirs]:
            for package_dir in package_dirset:
                for tik_file in system.BuildFileListByExtensions(package_dir, extensions = [".tik"]):
                    if tik_file.endswith("title.tik"):
                        tik_dir = system.GetFilenameDirectory(tik_file)
                        success = nintendo.InstallWiiUNusPackage(
                            nus_package_dir = tik_dir,
                            nand_dir = system.JoinPaths(programs.GetEmulatorPathConfigValue("Cemu", "setup_dir"), "mlc01"),
                            verbose = verbose,
                            pretend_run = pretend_run,
                            exit_on_failure = exit_on_failure)
                        if not success:
                            return False
        return True

    # Setup
    def Setup(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Download windows program
        if programs.ShouldProgramBeInstalled("Cemu", "windows"):
            success = release.DownloadGithubRelease(
                github_user = "cemu-project",
                github_repo = "Cemu",
                starts_with = "cemu",
                ends_with = "windows-x64.zip",
                search_file = "Cemu.exe",
                install_name = "Cemu",
                install_dir = programs.GetProgramInstallDir("Cemu", "windows"),
                backups_dir = programs.GetProgramBackupDir("Cemu", "windows"),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                system.LogError("Could not setup Cemu")
                return False

        # Download linux program
        if programs.ShouldProgramBeInstalled("Cemu", "linux"):
            success = release.DownloadGithubRelease(
                github_user = "cemu-project",
                github_repo = "Cemu",
                starts_with = "Cemu",
                ends_with = ".AppImage",
                install_name = "Cemu",
                install_dir = programs.GetProgramInstallDir("Cemu", "linux"),
                backups_dir = programs.GetProgramBackupDir("Cemu", "linux"),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                system.LogError("Could not setup Cemu")
                return False
        return True

    # Setup offline
    def SetupOffline(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Setup windows program
        if programs.ShouldProgramBeInstalled("Cemu", "windows"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetProgramBackupDir("Cemu", "windows"),
                install_name = "Cemu",
                install_dir = programs.GetProgramInstallDir("Cemu", "windows"),
                search_file = "Cemu.exe",
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                system.LogError("Could not setup Cemu")
                return False

        # Setup linux program
        if programs.ShouldProgramBeInstalled("Cemu", "linux"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetProgramBackupDir("Cemu", "linux"),
                install_name = "Cemu",
                install_dir = programs.GetProgramInstallDir("Cemu", "linux"),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                system.LogError("Could not setup Cemu")
                return False
        return True

    # Configure
    def Configure(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Create config files
        for config_filename, config_contents in config_files.items():
            success = system.TouchFile(
                src = system.JoinPaths(environment.GetEmulatorsRootDir(), config_filename),
                contents = config_contents.strip(),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                system.LogError("Could not setup Cemu config files")
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
        game_cache_dir = game_info.get_local_cache_dir()

        # Update keys
        for key_file in system.BuildFileListByExtensions(game_cache_dir, extensions = [".txt"]):
            if key_file.endswith(".key.txt"):
                for platform in ["windows", "linux"]:
                    nintendo.UpdateWiiUKeys(
                        src_key_file = key_file,
                        dest_key_file = programs.GetEmulatorPathConfigValue("Cemu", "keys_file", platform),
                        verbose = verbose,
                        pretend_run = pretend_run,
                        exit_on_failure = exit_on_failure)

        # Get launch command
        launch_cmd = [
            programs.GetEmulatorProgram("Cemu"),
            "-g", config.token_game_file
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
