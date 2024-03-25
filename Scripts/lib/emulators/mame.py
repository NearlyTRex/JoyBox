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
#
# CORE SEARCH PATH OPTIONS
#
homepath                  $EMULATOR_SETUP_ROOT
rompath                   $EMULATOR_SETUP_ROOT/roms
hashpath                  $EMULATOR_SETUP_ROOT/hash
samplepath                $EMULATOR_SETUP_ROOT/samples
artpath                   $EMULATOR_SETUP_ROOT/artwork
ctrlrpath                 $EMULATOR_SETUP_ROOT/ctrlr
inipath                   $EMULATOR_SETUP_ROOT;$EMULATOR_SETUP_ROOT/ini
fontpath                  $EMULATOR_SETUP_ROOT
cheatpath                 $EMULATOR_SETUP_ROOT/cheat
crosshairpath             $EMULATOR_SETUP_ROOT/crosshair
pluginspath               $EMULATOR_SETUP_ROOT/plugins
languagepath              $EMULATOR_SETUP_ROOT/language
swpath                    $EMULATOR_SETUP_ROOT/software

#
# CORE OUTPUT DIRECTORY OPTIONS
#
cfg_directory             $EMULATOR_SETUP_ROOT/cfg
nvram_directory           $EMULATOR_SETUP_ROOT/nvram
input_directory           $EMULATOR_SETUP_ROOT/inp
state_directory           $EMULATOR_SETUP_ROOT/sta
snapshot_directory        $EMULATOR_SETUP_ROOT/snap
diff_directory            $EMULATOR_SETUP_ROOT/diff
comment_directory         $EMULATOR_SETUP_ROOT/comments
share_directory           $EMULATOR_SETUP_ROOT/share
"""
config_files["Mame/windows/mame.ini"] = config_file_general
config_files["Mame/linux/Mame.AppImage.home/.mame/mame.ini"] = config_file_general

# System files
system_files = {}
system_files["roms/cdimono1.zip"] = "d69f6a7347b9acefc65dd0822b523335"
system_files["roms/videopac.zip"] = "a4fffe2ae1a7218939990430d378b059"
system_files["roms/a5200.zip"] = "b44173fbccbb5dfbd97fba4fe2f2abad"
system_files["roms/cdimono2.zip"] = "b3ccc0709e82aed4356e5d8a0948b4b9"
system_files["roms/a7800.zip"] = "68abbc5084df34defeceb323cc9685d9"
system_files["roms/gamecom.zip"] = "20506b663b593af57fb60364156b5b9f"
system_files["roms/intv_ecs.zip"] = "98c257fabbb97cbf3c1ff199746ee4cc"
system_files["roms/i8244.zip"] = "9fb6347babf9fc58578c56aa1e4d3dce"
system_files["roms/ti99_4a.zip"] = "091448bf43235a5cae113884c0263639"
system_files["roms/cdibios.zip"] = "f34b1f4badf6f587c91cb2505c3c531d"
system_files["roms/intv_voice.zip"] = "60140f3f7c4409e18a65fe2799f22f79"
system_files["roms/stic.zip"] = "2f4e36d03a8a2d9abaf3a94cb3583c8d"
system_files["roms/intv.zip"] = "20b954b1ba6b378965050b2e887df924"

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

    # Setup
    def Setup(self, verbose = False, exit_on_failure = False):

        # Download windows program
        if programs.ShouldProgramBeInstalled("Mame", "windows"):
            success = release.DownloadGithubRelease(
                github_user = "mamedev",
                github_repo = "mame",
                starts_with = "mame",
                ends_with = "64bit.exe",
                search_file = "mame.exe",
                install_name = "Mame",
                install_dir = programs.GetProgramInstallDir("Mame", "windows"),
                backups_dir = programs.GetProgramBackupDir("Mame", "windows"),
                installer_type = config.installer_type_7zip,
                release_type = config.release_type_archive,
                get_latest = True,
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup Mame")

        # Build linux program
        if programs.ShouldProgramBeInstalled("Mame", "linux"):
            success = release.BuildAppImageFromSource(
                release_url = "https://github.com/NearlyTRex/Mame.git",
                install_name = "Mame",
                install_dir = programs.GetProgramInstallDir("Mame", "linux"),
                backups_dir = programs.GetProgramBackupDir("Mame", "linux"),
                build_cmd = [
                    "make", "-j", "8"
                ],
                internal_copies = [
                    {"from": "Source/mame", "to": "AppImage/usr/bin/mame"},
                    {"from": "AppImageTool/linux/app.desktop", "to": "AppImage/app.desktop"},
                    {"from": "AppImageTool/linux/icon.svg", "to": "AppImage/icon.svg"}
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
            system.AssertCondition(success, "Could not setup Mame")

    # Setup offline
    def SetupOffline(self, verbose = False, exit_on_failure = False):

        # Setup windows program
        if programs.ShouldProgramBeInstalled("Mame", "windows"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetProgramBackupDir("Mame", "windows"),
                install_name = "Mame",
                install_dir = programs.GetProgramInstallDir("Mame", "windows"),
                search_file = "mame.exe",
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup Mame")

        # Setup linux program
        if programs.ShouldProgramBeInstalled("Mame", "linux"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetProgramBackupDir("Mame", "linux"),
                install_name = "Mame",
                install_dir = programs.GetProgramInstallDir("Mame", "linux"),
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup Mame")

    # Configure
    def Configure(self, verbose = False, exit_on_failure = False):

        # Create config files
        for config_filename, config_contents in config_files.items():
            success = system.TouchFile(
                src = os.path.join(environment.GetEmulatorsRootDir(), config_filename),
                contents = config_contents.strip(),
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup Mame config files")

        # Verify system files
        for filename, expected_md5 in system_files.items():
            actual_md5 = hashing.CalculateFileMD5(
                filename = os.path.join(environment.GetSyncedGameEmulatorSetupDir("Mame"), filename),
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            success = (expected_md5 == actual_md5)
            system.AssertCondition(success, "Could not verify Mame system file %s" % filename)

        # Copy system files
        for filename in system_files.keys():
            for platform in ["windows", "linux"]:
                success = system.SmartCopy(
                    src = os.path.join(environment.GetSyncedGameEmulatorSetupDir("Mame"), filename),
                    dest = os.path.join(programs.GetEmulatorPathConfigValue("Mame", "setup_dir", platform), filename),
                    verbose = verbose,
                    exit_on_failure = exit_on_failure)
                system.AssertCondition(success, "Could not setup Mame system files")

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

        # Get launch command
        launch_cmd = [programs.GetEmulatorProgram("Mame")]

        # Add ini path
        launch_cmd += [
            "-inipath", programs.GetEmulatorPathConfigValue("Mame", "config_dir")
        ]

        # Add rom path
        if game_platform == config.game_subcategory_arcade:
            launch_cmd += [
                "-rompath", config.token_game_dir
            ]
        else:
            launch_cmd += [
                "-rompath", programs.GetEmulatorPathConfigValue("Mame", "roms_dir")
            ]

        # Add launch file
        if game_platform == config.game_subcategory_arcade:
            launch_cmd += [
                config.token_game_name
            ]
        elif game_platform == config.game_subcategory_atari_5200:
            launch_cmd += [
                "a5200",
                "-cart", config.token_game_file
            ]
        elif game_platform == config.game_subcategory_atari_7800:
            launch_cmd += [
                "a7800",
                "-cart", config.token_game_file
            ]
        elif game_platform == config.game_subcategory_magnavox_odyssey_2:
            launch_cmd += [
                "odyssey2",
                "-cart", config.token_game_file
            ]
        elif game_platform == config.game_subcategory_mattel_intellivision:
            launch_cmd += [
                "intv",
                "-cart", config.token_game_file
            ]
        elif game_platform == config.game_subcategory_philips_cdi:
            launch_cmd += [
                "cdimono1",
                "-cdrom", config.token_game_file
            ]
        elif game_platform == config.game_subcategory_texas_instruments_ti994a:
            launch_cmd += [
                "ti99_4a",
                "-cart", config.token_game_file
            ]
        elif game_platform == config.game_subcategory_tiger_gamecom:
            launch_cmd += [
                "gamecom",
                "-cart1", config.token_game_file
            ]

        # Launch game
        emulatorcommon.SimpleLaunch(
            game_info = game_info,
            launch_cmd = launch_cmd,
            capture_type = capture_type,
            verbose = verbose,
            exit_on_failure = exit_on_failure)
