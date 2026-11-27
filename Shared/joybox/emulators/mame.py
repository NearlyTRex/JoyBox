# Local imports
from joybox import config
from joybox import environment
from joybox import fileops
from joybox import filebulk
from joybox import logger
from joybox import paths
from joybox import release
from joybox import sourcebuild
from joybox import programs
from joybox import gui
from joybox import emulatorcommon
from joybox import emulatorbase


# System drivers and media flags for non-arcade platforms
system_drivers = {
    config.Platform.OTHER_ATARI_5200: ("a5200", "-cart"),
    config.Platform.OTHER_ATARI_7800: ("a7800", "-cart"),
    config.Platform.OTHER_MAGNAVOX_ODYSSEY_2: ("odyssey2", "-cart"),
    config.Platform.OTHER_MATTEL_INTELLIVISION: ("intv", "-cart"),
    config.Platform.OTHER_PHILIPS_CDI: ("cdimono1", "-cdrom"),
    config.Platform.OTHER_TEXAS_INSTRUMENTS_TI994A: ("ti99_4a", "-cart"),
    config.Platform.OTHER_TIGER_GAMECOM: ("gamecom", "-cart1")
}

# Mame emulator
class Mame(emulatorbase.EmulatorBase):

    NAME = "Mame"

    # Windows build from the mamedev GitHub release's self-extracting exe; Linux AppImage built from the
    # NearlyTRex/Mame fork with make, its support dirs copied into the AppImage home
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
                ends_with = "x64.exe",
                search_file = "mame.exe",
                install_name = "Mame",
                install_dir = programs.get_program_install_dir("Mame", "windows"),
                backups_dir = programs.get_program_backup_dir("Mame", "windows"),
                release_type = config.ReleaseType.ARCHIVE,
                get_latest = True,
                locker_type = setup_params.locker_type,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup Mame")
                return False

        # Build linux program
        if programs.should_program_be_installed("Mame", "linux"):
            success = sourcebuild.build_appimage_from_source(
                release_url = "https://github.com/NearlyTRex/Mame.git",
                output_file = "App-x86_64.AppImage",
                install_name = "Mame",
                install_dir = programs.get_program_install_dir("Mame", "linux"),
                backups_dir = programs.get_program_backup_dir("Mame", "linux"),
                build_cmd = [
                    "make", "-j", "8"
                ],
                internal_copies = [
                    {"from": "Source/Mame/mame", "to": "AppImage/usr/bin/mame"},
                    {"from": "AppImageTool/linux/app.desktop", "to": "AppImage/app.desktop"},
                    {"from": "AppImageTool/linux/icon.svg", "to": "AppImage/icon.svg"}
                ],
                internal_symlinks = [
                    {"from": "usr/bin/mame", "to": "AppRun"}
                ],
                external_copies = [
                    {"from": "Source/Mame/uismall.bdf", "to": "Mame.AppImage.home/.mame/uismall.bdf"},
                    {"from": "Source/Mame/artwork", "to": "Mame.AppImage.home/.mame/artwork"},
                    {"from": "Source/Mame/bgfx", "to": "Mame.AppImage.home/.mame/bgfx"},
                    {"from": "Source/Mame/ctrlr", "to": "Mame.AppImage.home/.mame/ctrlr"},
                    {"from": "Source/Mame/docs", "to": "Mame.AppImage.home/.mame/docs"},
                    {"from": "Source/Mame/hash", "to": "Mame.AppImage.home/.mame/hash"},
                    {"from": "Source/Mame/hlsl", "to": "Mame.AppImage.home/.mame/hlsl"},
                    {"from": "Source/Mame/ini", "to": "Mame.AppImage.home/.mame/ini"},
                    {"from": "Source/Mame/language", "to": "Mame.AppImage.home/.mame/language"},
                    {"from": "Source/Mame/plugins", "to": "Mame.AppImage.home/.mame/plugins"},
                    {"from": "Source/Mame/roms", "to": "Mame.AppImage.home/.mame/roms"},
                    {"from": "Source/Mame/samples", "to": "Mame.AppImage.home/.mame/samples"}
                ],
                locker_type = setup_params.locker_type,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup Mame")
                return False
        return True

    # Install the Windows and Linux builds from the releases stored in their backups dirs
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

    # Write its config files, then verify the locker system files and copy them into each platform's setup dir
    def configure(self, setup_params = None):

        # Use default params if not provided
        if not setup_params:
            setup_params = config.SetupParams()

        # Create config files
        for config_filename, config_contents in self.get_config_files().items():
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
        if not self.verify_system_files(self.get_system_files(), setup_params):
            return False

        # Copy system files
        for filename in self.get_system_files().keys():
            for platform in ["windows", "linux"]:
                success = filebulk.smart_copy(
                    src = paths.join_paths(environment.get_locker_gaming_emulator_setup_dir("Mame"), filename),
                    dest = paths.join_paths(programs.get_emulator_path_config_value("Mame", "setup_dir", platform), filename),
                    verbose = setup_params.verbose,
                    pretend_run = setup_params.pretend_run,
                    exit_on_failure = setup_params.exit_on_failure)
                if not success:
                    logger.log_error("Could not setup Mame system files")
                    return False
        return True

    # Run MAME with its ini path; arcade games load by set name from the game dir, other platforms
    # through their system driver and media flag; windowed unless fullscreen is asked
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

        # Check if this platform is valid
        if game_platform not in self.get_platforms():
            gui.display_error_popup(
                title_text = "Launch platform not defined",
                message_text = "Launch platform %s not defined in Mame config" % game_platform)

        # Get launch command
        launch_cmd = [programs.get_emulator_program("Mame")]

        # Add ini path
        launch_cmd += [
            "-inipath", programs.get_emulator_path_config_value("Mame", "config_dir")
        ]

        # Add rom path and launch file
        if game_platform == config.Platform.OTHER_ARCADE:
            launch_cmd += [
                "-rompath", config.TOKEN_GAME_DIR,
                config.TOKEN_GAME_NAME
            ]
        else:
            system_name, media_flag = system_drivers[game_platform]
            launch_cmd += [
                "-rompath", programs.get_emulator_path_config_value("Mame", "roms_dir"),
                system_name,
                media_flag, config.TOKEN_GAME_FILE
            ]

        # Mame runs fullscreen unless told otherwise
        if not fullscreen:
            launch_cmd += [
                "-window"
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
