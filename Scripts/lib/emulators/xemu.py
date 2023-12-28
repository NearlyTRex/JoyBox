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
config_file_general = """
[general]
show_welcome = false

[input.bindings]
port1 = '030003f05e0400008e02000014010000'

[sys.files]
bootrom_path = '$EMULATOR_SETUP_ROOT/bios/mcpx_1.0.bin'
flashrom_path = '$EMULATOR_SETUP_ROOT/bios/complex_4627.bin'
eeprom_path = "$GAME_SAVE_DIR/eeprom.bin"
hdd_path = "$GAME_SAVE_DIR/xbox_hdd.qcow2"
"""
config_files["Xemu/windows/xemu.toml"] = config_file_general
config_files["Xemu/linux/Xemu.AppImage.home/.local/share/xemu/xemu/xemu.toml"] = config_file_general

# Xemu emulator
class Xemu(emulatorbase.EmulatorBase):

    # Get name
    def GetName(self):
        return "Xemu"

    # Get platforms
    def GetPlatforms(self):
        return [
            config.game_subcategory_microsoft_xbox
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
                "setup_files": [
                    {
                        "file": "bios/mcpx_1.0.bin",
                        "md5": "d49c52a4102f6df7bcf8d0617ac475ed"
                    },
                    {
                        "file": "bios/complex_4627.bin",
                        "md5": "ec00e31e746de2473acfe7903c5a4cb7"
                    },
                    {
                        "file": "bios/complex_4627_v1.03.bin",
                        "md5": "21445c6f28fca7285b0f167ea770d1e5"
                    }
                ],
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
    def Setup(self, verbose = False, exit_on_failure = False):

        # Download windows program
        if programs.ShouldProgramBeInstalled("Xemu", "windows"):
            success = network.DownloadLatestGithubRelease(
                github_user = "mborgerson",
                github_repo = "xemu",
                starts_with = "xemu",
                ends_with = "win-release.zip",
                search_file = "xemu.exe",
                install_name = "Xemu",
                install_dir = programs.GetProgramInstallDir("Xemu", "windows"),
                get_latest = True,
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup Xemu")

        # Build linux program
        if programs.ShouldProgramBeInstalled("Xemu", "linux"):
            success = network.BuildAppImageFromSource(
                release_url = "https://github.com/NearlyTRex/Xemu.git",
                output_name = "Xemu",
                output_dir = programs.GetProgramInstallDir("Xemu", "linux"),
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
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup Xemu")

        # Create config files
        for config_filename, config_contents in config_files.items():
            success = system.TouchFile(
                src = os.path.join(environment.GetEmulatorsRootDir(), config_filename),
                contents = config_contents.strip(),
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup Xemu config files")

        # Copy setup files
        for platform in ["windows", "linux"]:
            success = system.CopyContents(
                src = environment.GetSyncedGameEmulatorSetupDir("Xemu"),
                dest = programs.GetEmulatorPathConfigValue("Xemu", "setup_dir", platform),
                skip_existing = True,
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup Xemu system files")

    # Launch
    def Launch(
        self,
        game_info,
        capture_type,
        fullscreen = False,
        verbose = False,
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
        emulatorcommon.SimpleLaunch(
            game_info = game_info,
            launch_cmd = launch_cmd,
            capture_type = capture_type,
            verbose = verbose,
            exit_on_failure = exit_on_failure)
