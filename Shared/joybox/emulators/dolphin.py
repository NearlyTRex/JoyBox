# Imports
import os
import os.path

# Local imports
from joybox import config
from joybox import environment
from joybox import fileops
from joybox import logger
from joybox import release
from joybox import sourcebuild
from joybox import programs
from joybox import archive
from joybox.nintendo import wii
from joybox import paths
from joybox import emulatorcommon
from joybox import emulatorbase


# Dolphin emulator
class Dolphin(emulatorbase.EmulatorBase):

    NAME = "Dolphin"

    # Install add-ons
    def install_addons(self, dlc_dirs = None, update_dirs = None, verbose = False, pretend_run = False, exit_on_failure = False):
        dlc_dirs = [] if dlc_dirs is None else dlc_dirs
        update_dirs = [] if update_dirs is None else update_dirs
        for package_dirset in [dlc_dirs, update_dirs]:
            for package_dir in package_dirset:
                for wad_file in paths.build_file_list_by_extensions(package_dir, extensions = [".wad"]):
                    success = wii.install_wii_wad(
                        src_wad_file = wad_file,
                        nand_dir = paths.join_paths(programs.get_emulator_path_config_value("Dolphin", "setup_dir"), "Wii"),
                        verbose = verbose,
                        pretend_run = pretend_run,
                        exit_on_failure = exit_on_failure)
                    if not success:
                        return False
        return True

    # Windows build from the latest dolphin-emu.org download; Linux AppImage built from the
    # NearlyTRex/Dolphin fork with CMake
    def setup(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Download windows program
        if programs.should_program_be_installed("Dolphin", "windows"):
            success = release.download_webpage_release(
                webpage_url = "https://dolphin-emu.org/download",
                webpage_base_url = "https://dolphin-emu.org",
                starts_with = "https://dl.dolphin-emu.org/builds",
                ends_with = "x64.7z",
                search_file = "Dolphin.exe",
                install_name = "Dolphin",
                install_dir = programs.get_program_install_dir("Dolphin", "windows"),
                backups_dir = programs.get_program_backup_dir("Dolphin", "windows"),
                get_latest = True,
                locker_type = setup_params.locker_type,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup Dolphin")
                return False

        # Build linux program
        if programs.should_program_be_installed("Dolphin", "linux"):
            success = sourcebuild.build_appimage_from_source(
                release_url = "https://github.com/NearlyTRex/Dolphin.git",
                output_file = "Dolphin_Emulator-x86_64.AppImage",
                install_name = "Dolphin",
                install_dir = programs.get_program_install_dir("Dolphin", "linux"),
                backups_dir = programs.get_program_backup_dir("Dolphin", "linux"),
                build_cmd = [
                    "cmake", "..", "-DLINUX_LOCAL_DEV=true", "-DCMAKE_BUILD_TYPE=Release",
                    "&&",
                    "make", "-j", "4"
                ],
                build_dir = "Build",
                internal_copies = [
                    {"from": "Source/Dolphin/Build/Binaries/dolphin-emu", "to": "AppImage/usr/bin/dolphin-emu"},
                    {"from": "Source/Dolphin/Build/Binaries/dolphin-tool", "to": "AppImage/usr/bin/dolphin-tool"},
                    {"from": "Source/Dolphin/Data/Sys", "to": "AppImage/usr/bin/Sys"},
                    {"from": "Source/Dolphin/Data/dolphin-emu.desktop", "to": "AppImage/dolphin-emu.desktop"},
                    {"from": "Source/Dolphin/Data/dolphin-emu.png", "to": "AppImage/dolphin-emu.png"}
                ],
                internal_symlinks = [
                    {"from": "usr/bin/dolphin-emu", "to": "AppRun"}
                ],
                locker_type = setup_params.locker_type,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup Dolphin")
                return False
        return True

    # Install the Windows and Linux builds from the releases stored in their backups dirs
    def setup_offline(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Setup windows program
        if programs.should_program_be_installed("Dolphin", "windows"):
            success = release.setup_stored_release(
                archive_dir = programs.get_program_backup_dir("Dolphin", "windows"),
                install_name = "Dolphin",
                install_dir = programs.get_program_install_dir("Dolphin", "windows"),
                search_file = "Dolphin.exe",
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup Dolphin")
                return False

        # Setup linux program
        if programs.should_program_be_installed("Dolphin", "linux"):
            success = release.setup_stored_release(
                archive_dir = programs.get_program_backup_dir("Dolphin", "linux"),
                install_name = "Dolphin",
                install_dir = programs.get_program_install_dir("Dolphin", "linux"),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup Dolphin")
                return False
        return True

    # Write its config files, verify the locker system files, then unzip the Wii archive
    # into each platform's setup dir, keeping files already there
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
                logger.log_error("Could not setup Dolphin config files")
                return False

        # Verify system files
        if not self.verify_system_files(self.get_system_files(), setup_params):
            return False

        # Extract system files
        for platform in ["windows", "linux"]:
            for obj in ["Wii"]:
                if os.path.exists(paths.join_paths(environment.get_locker_gaming_emulator_setup_dir("Dolphin"), obj + config.ArchiveFileType.ZIP.cval())):
                    success = archive.extract_archive(
                        archive_file = paths.join_paths(environment.get_locker_gaming_emulator_setup_dir("Dolphin"), obj + config.ArchiveFileType.ZIP.cval()),
                        extract_dir = paths.join_paths(programs.get_emulator_path_config_value("Dolphin", "setup_dir", platform), obj),
                        skip_existing = True,
                        verbose = setup_params.verbose,
                        pretend_run = setup_params.pretend_run,
                        exit_on_failure = setup_params.exit_on_failure)
                    if not success:
                        logger.log_error("Could not extract Dolphin system files")
                        return False
        return True

    # Run Dolphin on the game file, turning on its fullscreen display option when asked
    def launch(
        self,
        game_info,
        capture_type = None,
        capture_file = None,
        fullscreen = False,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Get launch command
        launch_cmd = [
            programs.get_emulator_program("Dolphin"),
            config.TOKEN_GAME_FILE
        ]
        if fullscreen:
            launch_cmd += [
                "--config", "Dolphin.Display.Fullscreen=True"
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
