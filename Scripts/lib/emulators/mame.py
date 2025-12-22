# Imports
import os
import os.path
import sys

# Local imports
import config
import environment
import fileops
import system
import logger
import paths
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
homepath                  EMULATOR_SETUP_ROOT
rompath                   EMULATOR_SETUP_ROOT/roms
hashpath                  EMULATOR_SETUP_ROOT/hash
samplepath                EMULATOR_SETUP_ROOT/samples
artpath                   EMULATOR_SETUP_ROOT/artwork
ctrlrpath                 EMULATOR_SETUP_ROOT/ctrlr
inipath                   EMULATOR_SETUP_ROOT;EMULATOR_SETUP_ROOT/ini
fontpath                  EMULATOR_SETUP_ROOT
cheatpath                 EMULATOR_SETUP_ROOT/cheat
crosshairpath             EMULATOR_SETUP_ROOT/crosshair
pluginspath               EMULATOR_SETUP_ROOT/plugins
languagepath              EMULATOR_SETUP_ROOT/language
swpath                    EMULATOR_SETUP_ROOT/software

#
# CORE OUTPUT DIRECTORY OPTIONS
#
cfg_directory             EMULATOR_SETUP_ROOT/cfg
nvram_directory           EMULATOR_SETUP_ROOT/nvram
input_directory           EMULATOR_SETUP_ROOT/inp
state_directory           EMULATOR_SETUP_ROOT/sta
snapshot_directory        EMULATOR_SETUP_ROOT/snap
diff_directory            EMULATOR_SETUP_ROOT/diff
comment_directory         EMULATOR_SETUP_ROOT/comments
share_directory           EMULATOR_SETUP_ROOT/share
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
    def get_name(self):
        return "Mame"

    # Get platforms
    def get_platforms(self):
        return [
            config.Platform.OTHER_ARCADE,
            config.Platform.OTHER_ATARI_5200,
            config.Platform.OTHER_ATARI_7800,
            config.Platform.OTHER_MAGNAVOX_ODYSSEY_2,
            config.Platform.OTHER_MATTEL_INTELLIVISION,
            config.Platform.OTHER_PHILIPS_CDI,
            config.Platform.OTHER_TEXAS_INSTRUMENTS_TI994A,
            config.Platform.OTHER_TIGER_GAMECOM
        ]

    # Get config
    def get_config(self):
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
    def setup(self, setup_params = None):

        # Use default params if not provided
        if not setup_params:
            setup_params = config.SetupParams()

        # Download windows program
        if programs.should_program_be_installed("Mame", "windows"):
            success = release.download_github_release(
                github_user = "mamedev",
                github_repo = "mame",
                starts_with = "mame",
                ends_with = "64bit.exe",
                search_file = "mame.exe",
                install_name = "Mame",
                install_dir = programs.get_program_install_dir("Mame", "windows"),
                backups_dir = programs.get_program_backup_dir("Mame", "windows"),
                installer_type = config.InstallerType.SEVENZIP,
                release_type = config.ReleaseType.ARCHIVE,
                get_latest = True,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup Mame")
                return False

        # Build linux program
        if programs.should_program_be_installed("Mame", "linux"):
            success = release.build_appimage_from_source(
                release_url = "https://github.com/NearlyTRex/Mame.git",
                output_file = "App-x86_64.AppImage",
                install_name = "Mame",
                install_dir = programs.get_program_install_dir("Mame", "linux"),
                backups_dir = programs.get_program_backup_dir("Mame", "linux"),
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
                locker_type = setup_params.locker_type,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup Mame")
                return False
        return True

    # Setup offline
    def setup_offline(self, setup_params = None):

        # Use default params if not provided
        if not setup_params:
            setup_params = config.SetupParams()

        # Setup windows program
        if programs.should_program_be_installed("Mame", "windows"):
            success = release.setup_stored_release(
                archive_dir = programs.get_program_backup_dir("Mame", "windows"),
                install_name = "Mame",
                install_dir = programs.get_program_install_dir("Mame", "windows"),
                search_file = "mame.exe",
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup Mame")
                return False

        # Setup linux program
        if programs.should_program_be_installed("Mame", "linux"):
            success = release.setup_stored_release(
                archive_dir = programs.get_program_backup_dir("Mame", "linux"),
                install_name = "Mame",
                install_dir = programs.get_program_install_dir("Mame", "linux"),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup Mame")
                return False
        return True

    # Configure
    def configure(self, setup_params = None):

        # Use default params if not provided
        if not setup_params:
            setup_params = config.SetupParams()

        # Create config files
        for config_filename, config_contents in config_files.items():
            success = fileops.touch_file(
                src = paths.join_paths(environment.get_emulators_root_dir(), config_filename),
                contents = config_contents.strip(),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup Mame config files")
                return False

        # Verify system files
        for filename, expected_md5 in system_files.items():
            actual_md5 = hashing.calculate_file_md5(
                src = paths.join_paths(environment.get_locker_gaming_emulator_setup_dir("Mame"), filename),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            success = (expected_md5 == actual_md5)
            if not success:
                logger.log_error("Could not verify Mame system file %s" % filename)
                return False

        # Copy system files
        for filename in system_files.keys():
            for platform in ["windows", "linux"]:
                success = fileops.smart_copy(
                    src = paths.join_paths(environment.get_locker_gaming_emulator_setup_dir("Mame"), filename),
                    dest = paths.join_paths(programs.get_emulator_path_config_value("Mame", "setup_dir", platform), filename),
                    verbose = setup_params.verbose,
                    pretend_run = setup_params.pretend_run,
                    exit_on_failure = setup_params.exit_on_failure)
                if not success:
                    logger.log_error("Could not setup Mame system files")
                    return False
        return True

    # Launch
    def launch(
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

        # Get launch command
        launch_cmd = [programs.get_emulator_program("Mame")]

        # Add ini path
        launch_cmd += [
            "-inipath", programs.get_emulator_path_config_value("Mame", "config_dir")
        ]

        # Add rom path
        if game_platform == config.Platform.OTHER_ARCADE:
            launch_cmd += [
                "-rompath", config.token_game_dir
            ]
        else:
            launch_cmd += [
                "-rompath", programs.get_emulator_path_config_value("Mame", "roms_dir")
            ]

        # Add launch file
        if game_platform == config.Platform.OTHER_ARCADE:
            launch_cmd += [
                config.token_game_name
            ]
        elif game_platform == config.Platform.OTHER_ATARI_5200:
            launch_cmd += [
                "a5200",
                "-cart", config.token_game_file
            ]
        elif game_platform == config.Platform.OTHER_ATARI_7800:
            launch_cmd += [
                "a7800",
                "-cart", config.token_game_file
            ]
        elif game_platform == config.Platform.OTHER_MAGNAVOX_ODYSSEY_2:
            launch_cmd += [
                "odyssey2",
                "-cart", config.token_game_file
            ]
        elif game_platform == config.Platform.OTHER_MATTEL_INTELLIVISION:
            launch_cmd += [
                "intv",
                "-cart", config.token_game_file
            ]
        elif game_platform == config.Platform.OTHER_PHILIPS_CDI:
            launch_cmd += [
                "cdimono1",
                "-cdrom", config.token_game_file
            ]
        elif game_platform == config.Platform.OTHER_TEXAS_INSTRUMENTS_TI994A:
            launch_cmd += [
                "ti99_4a",
                "-cart", config.token_game_file
            ]
        elif game_platform == config.Platform.OTHER_TIGER_GAMECOM:
            launch_cmd += [
                "gamecom",
                "-cart1", config.token_game_file
            ]

        # Launch game
        return emulatorcommon.simple_launch(
            game_info = game_info,
            launch_cmd = launch_cmd,
            capture_type = capture_type,
            capture_file = capture_file,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
