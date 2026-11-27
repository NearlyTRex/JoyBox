# Imports
import os
import os.path

# Local imports
from joybox import config
from joybox import environment
from joybox import fileops
from joybox import filebulk
from joybox import logger
from joybox import paths
from joybox import release
from joybox import programs
from joybox import gui
from joybox import emulatorcommon
from joybox import emulatorbase


# RetroArch emulator
class RetroArch(emulatorbase.EmulatorBase):

    NAME = "RetroArch"

    # Download the nightly RetroArch program and cores 7z archives for Windows and Linux
    # from buildbot.libretro.com
    def setup(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Download windows program
        if programs.should_program_be_installed("RetroArch", "windows"):
            success = release.download_general_release(
                archive_url = "https://buildbot.libretro.com/nightly/windows/x86_64/RetroArch.7z",
                search_file = "retroarch.exe",
                install_name = "RetroArch",
                install_dir = programs.get_program_install_dir("RetroArch", "windows"),
                backups_dir = programs.get_program_backup_dir("RetroArch", "windows"),
                locker_type = setup_params.locker_type,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup RetroArch")
                return False
            success = release.download_general_release(
                archive_url = "https://buildbot.libretro.com/nightly/windows/x86_64/RetroArch_cores.7z",
                search_file = "snes9x_libretro.dll",
                install_name = "RetroArch",
                install_dir = programs.get_emulator_path_config_value("RetroArch", "cores_dir", "windows"),
                backups_dir = programs.get_program_backup_dir("RetroArch", "windows"),
                locker_type = setup_params.locker_type,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup RetroArch cores")
                return False

        # Download linux program
        if programs.should_program_be_installed("RetroArch", "linux"):
            success = release.download_general_release(
                archive_url = "https://buildbot.libretro.com/nightly/linux/x86_64/RetroArch.7z",
                search_file = "RetroArch-Linux-x86_64.AppImage",
                install_name = "RetroArch",
                install_dir = programs.get_program_install_dir("RetroArch", "linux"),
                backups_dir = programs.get_program_backup_dir("RetroArch", "linux"),
                locker_type = setup_params.locker_type,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup RetroArch")
                return False
            success = release.download_general_release(
                archive_url = "https://buildbot.libretro.com/nightly/linux/x86_64/RetroArch_cores.7z",
                search_file = "snes9x_libretro.so",
                install_name = "RetroArch",
                install_dir = programs.get_emulator_path_config_value("RetroArch", "cores_dir", "linux"),
                backups_dir = programs.get_program_backup_dir("RetroArch", "linux"),
                locker_type = setup_params.locker_type,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup RetroArch cores")
                return False
        return True

    # Install the program and cores for Windows and Linux from the archives stored in their backups dirs
    def setup_offline(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Setup windows program
        if programs.should_program_be_installed("RetroArch", "windows"):
            success = release.setup_stored_release(
                archive_dir = programs.get_program_backup_dir("RetroArch", "windows"),
                install_name = "RetroArch",
                install_dir = programs.get_program_install_dir("RetroArch", "windows"),
                preferred_archive = "RetroArch.7z",
                search_file = "retroarch.exe",
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup RetroArch")
                return False
            success = release.setup_stored_release(
                archive_dir = programs.get_program_backup_dir("RetroArch", "windows"),
                install_name = "RetroArch",
                install_dir = programs.get_emulator_path_config_value("RetroArch", "cores_dir", "windows"),
                preferred_archive = "RetroArch_cores.7z",
                search_file = "snes9x_libretro.dll",
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup RetroArch cores")
                return False

        # Setup linux program
        if programs.should_program_be_installed("RetroArch", "linux"):
            success = release.setup_stored_release(
                archive_dir = programs.get_program_backup_dir("RetroArch", "linux"),
                install_name = "RetroArch",
                install_dir = programs.get_program_install_dir("RetroArch", "linux"),
                preferred_archive = "RetroArch.7z",
                search_file = "RetroArch-Linux-x86_64.AppImage",
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup RetroArch")
                return False
            success = release.setup_stored_release(
                archive_dir = programs.get_program_backup_dir("RetroArch", "linux"),
                install_name = "RetroArch",
                install_dir = programs.get_emulator_path_config_value("RetroArch", "cores_dir", "linux"),
                preferred_archive = "RetroArch_cores.7z",
                search_file = "snes9x_libretro.so",
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup RetroArch cores")
                return False
        return True

    # Write its config files, then verify the locker system files and copy them into each platform's setup dir
    def configure(self, setup_params = None):
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
                logger.log_error("Could not setup RetroArch config files")
                return False

        # Verify system files
        if not self.verify_system_files(self.get_system_files(), setup_params):
            return False

        # Copy system files
        for filename in self.get_system_files().keys():
            for platform in ["windows", "linux"]:
                success = filebulk.smart_copy(
                    src = paths.join_paths(environment.get_locker_gaming_emulator_setup_dir("RetroArch"), filename),
                    dest = paths.join_paths(programs.get_emulator_path_config_value("RetroArch", "setup_dir", platform), filename),
                    verbose = setup_params.verbose,
                    pretend_run = setup_params.pretend_run,
                    exit_on_failure = setup_params.exit_on_failure)
                if not success:
                    logger.log_error("Could not setup RetroArch system files")
                    return False
        return True

    # Run RetroArch with -L on the core its cores_mapping names for the platform;
    # quits with an error popup when the platform has no core or the core file is missing
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

        # Get core info
        cores_dir = programs.get_emulator_path_config_value("RetroArch", "cores_dir")
        cores_ext = programs.get_emulator_config_value("RetroArch", "cores_ext")
        cores_mapping = programs.get_emulator_config_value("RetroArch", "cores_mapping")

        # Check if this platform is valid
        if game_platform not in cores_mapping:
            gui.display_error_popup(
                title_text = "Launch platform not defined",
                message_text = "Launch platform %s not defined in RetroArch config" % game_platform)

        # Check if core is installed
        core_file = paths.join_paths(cores_dir, cores_mapping[game_platform] + cores_ext)
        if not os.path.exists(core_file):
            gui.display_error_popup(
                title_text = "RetroArch core not found",
                message_text = "RetroArch core '%s' could not be found!" % cores_mapping[game_platform])

        # Get launch command
        launch_cmd = [
            programs.get_emulator_program("RetroArch"),
            "-L", core_file,
            config.TOKEN_GAME_FILE
        ]
        if fullscreen:
            launch_cmd += [
                "-f"
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
