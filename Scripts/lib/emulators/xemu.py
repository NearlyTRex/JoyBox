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
config_file_general = """
[general]
show_welcome = false

[input.bindings]
port1 = '030003f05e0400008e02000014010000'

[sys.files]
bootrom_path = 'EMULATOR_SETUP_ROOT/bios/mcpx_1.0.bin'
flashrom_path = 'EMULATOR_SETUP_ROOT/bios/complex_4627.bin'
eeprom_path = "GAME_SAVE_DIR/eeprom.bin"
hdd_path = "GAME_SAVE_DIR/xbox_hdd.qcow2"
"""
config_files["Xemu/windows/xemu.toml"] = config_file_general
config_files["Xemu/linux/Xemu.AppImage.home/.local/share/xemu/xemu/xemu.toml"] = config_file_general

# System files
system_files = {}
system_files["bios/mcpx_1.0.bin"] = "d49c52a4102f6df7bcf8d0617ac475ed"
system_files["bios/complex_4627.bin"] = "ec00e31e746de2473acfe7903c5a4cb7"
system_files["bios/complex_4627_v1.03.bin"] = "21445c6f28fca7285b0f167ea770d1e5"

# Xemu emulator
class Xemu(emulatorbase.EmulatorBase):

    # Get name
    def GetName(self):
        return "Xemu"

    # Get platforms
    def GetPlatforms(self):
        return [
            config.Platform.MICROSOFT_XBOX
        ]

    # Get config
    def GetConfig(self):
        return {
            "Xemu": {
                "program": {
                    "windows": "Xemu/windows/xemu.exe",
                    "linux": "Xemu/linux/Xemu.AppImage"
                },
                "save_dir": {
                    "windows": None,
                    "linux": None
                },
                "setup_dir": {
                    "windows": "Xemu/windows",
                    "linux": "Xemu/linux/Xemu.AppImage.home/.local/share/xemu/xemu"
                },
                "config_file": {
                    "windows": "Xemu/windows/xemu.toml",
                    "linux": "Xemu/linux/Xemu.AppImage.home/.local/share/xemu/xemu/xemu.toml"
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
        if programs.ShouldProgramBeInstalled("Xemu", "windows"):
            success = release.DownloadGithubRelease(
                github_user = "mborgerson",
                github_repo = "xemu",
                starts_with = "xemu",
                ends_with = "win-release.zip",
                search_file = "xemu.exe",
                install_name = "Xemu",
                install_dir = programs.GetProgramInstallDir("Xemu", "windows"),
                backups_dir = programs.GetProgramBackupDir("Xemu", "windows"),
                get_latest = True,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                system.LogError("Could not setup Xemu")
                return False

        # Build linux program
        if programs.ShouldProgramBeInstalled("Xemu", "linux"):
            success = release.BuildAppImageFromSource(
                release_url = "https://github.com/NearlyTRex/Xemu.git",
                output_file = "xemu-x86_64.AppImage",
                install_name = "Xemu",
                install_dir = programs.GetProgramInstallDir("Xemu", "linux"),
                backups_dir = programs.GetProgramBackupDir("Xemu", "linux"),
                build_cmd = [
                    "./build.sh"
                ],
                internal_copies = [
                    {"from": "Source/dist/xemu", "to": "AppImage/usr/bin/xemu"},
                    {"from": "Source/ui/xemu.desktop", "to": "AppImage/xemu.desktop"},
                    {"from": "Source/ui/icons/xemu.svg", "to": "AppImage/xemu.svg"}
                ],
                internal_symlinks = [
                    {"from": "usr/bin/xemu", "to": "AppRun"}
                ],
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                system.LogError("Could not setup Xemu")
                return False
        return True

    # Setup offline
    def SetupOffline(self, verbose = False, pretend_run = False, exit_on_failure = False):

        # Setup windows program
        if programs.ShouldProgramBeInstalled("Xemu", "windows"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetProgramBackupDir("Xemu", "windows"),
                install_name = "Xemu",
                install_dir = programs.GetProgramInstallDir("Xemu", "windows"),
                search_file = "xemu.exe",
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                system.LogError("Could not setup Xemu")
                return False

        # Setup linux program
        if programs.ShouldProgramBeInstalled("Xemu", "linux"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetProgramBackupDir("Xemu", "linux"),
                install_name = "Xemu",
                install_dir = programs.GetProgramInstallDir("Xemu", "linux"),
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                system.LogError("Could not setup Xemu")
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
                system.LogError("Could not setup Xemu config files")
                return False

        # Verify system files
        for filename, expected_md5 in system_files.items():
            actual_md5 = hashing.CalculateFileMD5(
                src = system.JoinPaths(environment.GetLockerGamingEmulatorSetupDir("Xemu"), filename),
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            success = (expected_md5 == actual_md5)
            if not success:
                system.LogError("Could not verify Xemu system file %s" % filename)
                return False

        # Copy system files
        for filename in system_files.keys():
            for platform in ["windows", "linux"]:
                success = system.SmartCopy(
                    src = system.JoinPaths(environment.GetLockerGamingEmulatorSetupDir("Xemu"), filename),
                    dest = system.JoinPaths(programs.GetEmulatorPathConfigValue("Xemu", "setup_dir", platform), filename),
                    verbose = verbose,
                    pretend_run = pretend_run,
                    exit_on_failure = exit_on_failure)
                if not success:
                    system.LogError("Could not setup Xemu system files")
                    return False
        return True

    # Launch
    def Launch(
        self,
        game_info,
        capture_type,
        fullscreen = False,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Get launch command
        launch_cmd = [
            programs.GetEmulatorProgram("Xemu"),
            "-dvd_path", config.token_game_file
        ]
        if fullscreen:
            launch_cmd += [
                "-full-screen"
            ]

        # Launch game
        return emulatorcommon.SimpleLaunch(
            game_info = game_info,
            launch_cmd = launch_cmd,
            capture_type = capture_type,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
