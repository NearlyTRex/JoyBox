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
config_files["Mame/windows/mame.ini"] = """
#
# CORE SEARCH PATH OPTIONS
#
homepath                  .
rompath                   roms
hashpath                  hash
samplepath                samples
artpath                   artwork
ctrlrpath                 ctrlr
inipath                   .;ini;ini/presets
fontpath                  .
cheatpath                 cheat
crosshairpath             crosshair
pluginspath               plugins
languagepath              language
swpath                    software

#
# CORE OUTPUT DIRECTORY OPTIONS
#
cfg_directory             cfg
nvram_directory           nvram
input_directory           inp
state_directory           sta
snapshot_directory        snap
diff_directory            diff
comment_directory         comments
share_directory           share
"""
config_files["Mame/linux/Mame.AppImage.home/.mame/mame.ini"] = """
#
# CORE SEARCH PATH OPTIONS
#
homepath                  $HOME/.mame
rompath                   $HOME/.mame/roms
hashpath                  $HOME/.mame/hash
samplepath                $HOME/.mame/samples
artpath                   $HOME/.mame/artwork
ctrlrpath                 $HOME/.mame/ctrlr
inipath                   $HOME/.mame;$HOME/.mame/ini
fontpath                  $HOME/.mame
cheatpath                 $HOME/.mame/cheat
crosshairpath             $HOME/.mame/crosshair
pluginspath               $HOME/.mame/plugins
languagepath              $HOME/.mame/language
swpath                    $HOME/.mame/software

#
# CORE OUTPUT DIRECTORY OPTIONS
#
cfg_directory             $HOME/.mame/cfg
nvram_directory           $HOME/.mame/nvram
input_directory           $HOME/.mame/inp
state_directory           $HOME/.mame/sta
snapshot_directory        $HOME/.mame/snap
diff_directory            $HOME/.mame/diff
comment_directory         $HOME/.mame/comments
share_directory           $HOME/.mame/share
"""

# Mame emulator
class Mame(emulatorbase.EmulatorBase):

    # Get name
    def GetName(self):
        return "Mame"

    # Get platforms
    def GetPlatforms(self):
        return [
            config.game_subcategory_arcade,
            config.game_subcategory_atari_5200,
            config.game_subcategory_atari_7800,
            config.game_subcategory_magnavox_odyssey_2,
            config.game_subcategory_mattel_intellivision,
            config.game_subcategory_philips_cdi,
            config.game_subcategory_texas_instruments_ti994a,
            config.game_subcategory_tiger_gamecom
        ]

    # Get config
    def GetConfig(self):
        return {
            "Mame": {
                "program": {
                    "windows": "Mame/windows/mame.exe",
                    "linux": "Mame/linux/Mame.AppImage"
                },
                "save_dir": {
                    "windows": None,
                    "linux": None
                },
                "setup_dir": {
                    "windows": "Mame/windows",
                    "linux": "Mame/linux/Mame.AppImage.home/.mame"
                },
                "config_dir": {
                    "windows": "Mame/windows",
                    "linux": "Mame/linux/Mame.AppImage.home/.mame"
                },
                "config_file": {
                    "windows": "Mame/windows/mame.ini",
                    "linux": "Mame/linux/Mame.AppImage.home/.mame/mame.ini"
                },
                "roms_dir": {
                    "windows": "Mame/windows/roms",
                    "linux": "Mame/linux/Mame.AppImage.home/.mame/roms"
                },
                "run_sandboxed": {
                    "windows": False,
                    "linux": False
                }
            }
        }

    # Download
    def Download(self, force_downloads = False, verbose = False, exit_on_failure = False):
        if force_downloads or programs.ShouldProgramBeInstalled("Mame", "windows"):
            network.DownloadLatestGithubRelease(
                github_user = "mamedev",
                github_repo = "mame",
                starts_with = "mame",
                ends_with = "64bit.exe",
                search_file = "mame.exe",
                install_name = "Mame",
                install_dir = programs.GetProgramInstallDir("Mame", "windows"),
                installer_type = config.installer_format_7zip,
                is_installer = False,
                is_archive = True,
                get_latest = True,
                verbose = verbose,
                exit_on_failure = exit_on_failure)
        if force_downloads or programs.ShouldProgramBeInstalled("Mame", "linux"):
            network.BuildAppImageFromSource(
                release_url = "https://github.com/mamedev/mame.git",
                output_name = "Mame",
                output_dir = programs.GetProgramInstallDir("Mame", "linux"),
                build_cmd = [
                    "make", "-j", "8"
                ],
                internal_copies = [
                    {"from": "Source/mame", "to": "AppImage/usr/bin/mame"},
                    {"from": "AppImageTool/linux/app.desktop", "to": "AppImage/app.desktop"},
                    {"from": "AppImageTool/linux/icon.png", "to": "AppImage/icon.png"}
                ],
                internal_symlinks = [
                    {"from": "usr/bin/mame", "to": "AppRun"}
                ],
                external_copies = [
                    {"from": "Source/uismall.bdf", "to": "Mame.AppImage.home/.mame/uismall.bdf"},
                    {"from": "Source/artwork", "to": "Mame.AppImage.home/.mame/artwork"},
                    {"from": "Source/bgfx", "to": "Mame.AppImage.home/.mame/bgfx"},
                    {"from": "Source/ctrlr", "to": "Mame.AppImage.home/.mame/ctrlr"},
                    {"from": "Source/docs", "to": "Mame.AppImage.home/.mame/docs"},
                    {"from": "Source/hash", "to": "Mame.AppImage.home/.mame/hash"},
                    {"from": "Source/hlsl", "to": "Mame.AppImage.home/.mame/hlsl"},
                    {"from": "Source/ini", "to": "Mame.AppImage.home/.mame/ini"},
                    {"from": "Source/language", "to": "Mame.AppImage.home/.mame/language"},
                    {"from": "Source/plugins", "to": "Mame.AppImage.home/.mame/plugins"},
                    {"from": "Source/roms", "to": "Mame.AppImage.home/.mame/roms"},
                    {"from": "Source/samples", "to": "Mame.AppImage.home/.mame/samples"}
                ],
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
                src = environment.GetSyncedGameEmulatorSetupDir("Mame"),
                dest = programs.GetEmulatorPathConfigValue("Mame", "setup_dir", platform),
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

        # Get launch command
        launch_cmd = [programs.GetEmulatorProgram("Mame")]

        # Add ini path
        launch_cmd += [
            "-inipath", programs.GetEmulatorPathConfigValue("Mame", "config_dir")
        ]

        # Add rom path
        if launch_platform == config.game_subcategory_arcade:
            launch_cmd += [
                "-rompath", config.token_game_dir
            ]
        else:
            launch_cmd += [
                "-rompath", programs.GetEmulatorPathConfigValue("Mame", "roms_dir")
            ]

        # Add launch file
        if launch_platform == config.game_subcategory_arcade:
            launch_cmd += [
                config.token_game_name
            ]
        elif launch_platform == config.game_subcategory_atari_5200:
            launch_cmd += [
                "a5200",
                "-cart", config.token_game_file
            ]
        elif launch_platform == config.game_subcategory_atari_7800:
            launch_cmd += [
                "a7800",
                "-cart", config.token_game_file
            ]
        elif launch_platform == config.game_subcategory_magnavox_odyssey_2:
            launch_cmd += [
                "odyssey2",
                "-cart", config.token_game_file
            ]
        elif launch_platform == config.game_subcategory_mattel_intellivision:
            launch_cmd += [
                "intv",
                "-cart", config.token_game_file
            ]
        elif launch_platform == config.game_subcategory_philips_cdi:
            launch_cmd += [
                "cdimono1",
                "-cdrom", config.token_game_file
            ]
        elif launch_platform == config.game_subcategory_texas_instruments_ti994a:
            launch_cmd += [
                "ti99_4a",
                "-cart", config.token_game_file
            ]
        elif launch_platform == config.game_subcategory_tiger_gamecom:
            launch_cmd += [
                "gamecom",
                "-cart1", config.token_game_file
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