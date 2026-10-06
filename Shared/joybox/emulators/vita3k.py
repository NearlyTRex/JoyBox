# Imports
import os
import os.path

# Local imports
import joybox.config as config
import joybox.environment as environment
import joybox.fileops as fileops
import joybox.logger as logger
import joybox.paths as paths
import joybox.release as release
import joybox.programs as programs
import joybox.archive as archive
import joybox.playstation as playstation
import joybox.emulatorcommon as emulatorcommon
import joybox.emulatorbase as emulatorbase

# Config files
config_files = {}
config_file_general = """
---
pref-path: EMULATOR_SETUP_ROOT
...
"""
config_files["Vita3K/windows/config.yml"] = config_file_general
config_files["Vita3K/linux/Vita3K.AppImage.home/.config/Vita3K/config.yml"] = config_file_general

# System files
system_files = {}
system_files["vs0.zip"] = "f3c4ec664b6a2cba130eb5b3977dbc23"
system_files["os0.zip"] = "301589989b48da90e6db41b85d2b0acc"
system_files["sa0.zip"] = "c248704ab44184c7c47f9bcc27854696"

# Vita3K emulator
class Vita3K(emulatorbase.EmulatorBase):

    # Get name
    def get_name(self):
        return "Vita3K"

    # Get platforms
    def get_platforms(self):
        return [
            config.Platform.SONY_PLAYSTATION_NETWORK_PSV,
            config.Platform.SONY_PLAYSTATION_VITA
        ]

    # Get config
    def get_config(self):
        return {
            "Vita3K": {
                "program": {
                    "windows": "Vita3K/windows/Vita3K.exe",
                    "linux": "Vita3K/linux/Vita3K.AppImage"
                },
                "save_dir": {
                    "windows": "Vita3K/windows/data/ux0/user",
                    "linux": "Vita3K/linux/Vita3K.AppImage.home/.local/share/Vita3K/Vita3K/ux0/user"
                },
                "app_dir": {
                    "windows": "Vita3K/windows/data/ux0/app",
                    "linux": "Vita3K/linux/Vita3K.AppImage.home/.local/share/Vita3K/Vita3K/ux0/app"
                },
                "setup_dir": {
                    "windows": "Vita3K/windows/data",
                    "linux": "Vita3K/linux/Vita3K.AppImage.home/.local/share/Vita3K/Vita3K"
                },
                "config_file": {
                    "windows": "Vita3K/windows/config.yml",
                    "linux": "Vita3K/linux/Vita3K.AppImage.home/.config/Vita3K/config.yml"
                },
                "run_sandboxed": {
                    "windows": False,
                    "linux": False
                }
            }
        }

    # Setup
    def setup(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Download windows program
        if programs.should_program_be_installed("Vita3K", "windows"):
            success = release.download_github_release(
                github_user = "Vita3K",
                github_repo = "Vita3K",
                starts_with = "windows-latest",
                ends_with = ".zip",
                search_file = "Vita3K.exe",
                install_name = "Vita3K",
                install_dir = programs.get_program_install_dir("Vita3K", "windows"),
                backups_dir = programs.get_program_backup_dir("Vita3K", "windows"),
                get_latest = True,
                locker_type = setup_params.locker_type,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup Vita3K")
                return False

        # Download linux program
        if programs.should_program_be_installed("Vita3K", "linux"):
            success = release.download_github_release(
                github_user = "Vita3K",
                github_repo = "Vita3K",
                starts_with = "Vita3K-x86_64",
                ends_with = ".AppImage",
                install_name = "Vita3K",
                install_dir = programs.get_program_install_dir("Vita3K", "linux"),
                backups_dir = programs.get_program_backup_dir("Vita3K", "linux"),
                get_latest = True,
                locker_type = setup_params.locker_type,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup Vita3K")
                return False
        return True

    # Setup offline
    def setup_offline(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Setup windows program
        if programs.should_program_be_installed("Vita3K", "windows"):
            success = release.setup_stored_release(
                archive_dir = programs.get_program_backup_dir("Vita3K", "windows"),
                install_name = "Vita3K",
                install_dir = programs.get_program_install_dir("Vita3K", "windows"),
                search_file = "Vita3K.exe",
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup Vita3K")
                return False

        # Setup linux program
        if programs.should_program_be_installed("Vita3K", "linux"):
            success = release.setup_stored_release(
                archive_dir = programs.get_program_backup_dir("Vita3K", "linux"),
                install_name = "Vita3K",
                install_dir = programs.get_program_install_dir("Vita3K", "linux"),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup Vita3K")
                return False
        return True

    # Configure
    def configure(self, setup_params = None):
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
                logger.log_error("Could not setup Vita3K config files")
                return False

        # Verify system files
        if not self.verify_system_files(system_files, setup_params):
            return False

        # Extract system files
        for platform in ["windows", "linux"]:
            for obj in ["os0", "sa0", "vs0"]:
                if os.path.exists(paths.join_paths(environment.get_locker_gaming_emulator_setup_dir("Vita3K"), obj + config.ArchiveFileType.ZIP.cval())):
                    success = archive.extract_archive(
                        archive_file = paths.join_paths(environment.get_locker_gaming_emulator_setup_dir("Vita3K"), obj + config.ArchiveFileType.ZIP.cval()),
                        extract_dir = paths.join_paths(programs.get_emulator_path_config_value("Vita3K", "setup_dir", platform), obj),
                        skip_existing = True,
                        verbose = setup_params.verbose,
                        pretend_run = setup_params.pretend_run,
                        exit_on_failure = setup_params.exit_on_failure)
                    if not success:
                        logger.log_error("Could not extract Vita3K system files")
                        return False
        return True

    # Stage work.bin where the Vita3K installer reads it
    def stage_workbin(self, cache_dir, content_root, verbose, pretend_run, exit_on_failure):
        src_workbin = paths.join_paths(cache_dir, "work.bin")
        package_dir = paths.join_paths(content_root, "sce_sys", "package")
        if not os.path.isfile(src_workbin) or os.path.isfile(paths.join_paths(package_dir, "work.bin")):
            return True
        success = fileops.make_directory(
            src = package_dir,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return False
        return fileops.copy_file_or_directory(
            src = src_workbin,
            dest = paths.join_paths(package_dir, "work.bin"),
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

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

        # Get title id
        title_id = game_info.get_launch_name()
        if not title_id:
            logger.log_error("Vita3K needs the game's title id as its launch name")
            return False

        # Get launch command
        launch_cmd = [programs.get_emulator_program("Vita3K")]
        if fullscreen:
            launch_cmd += ["-F"]

        # Run installed app
        if os.path.isdir(paths.join_paths(programs.get_emulator_path_config_value("Vita3K", "app_dir"), title_id)):
            launch_cmd += ["-r", config.token_game_name]

        # Install and run from the cache
        else:
            cache_dir = game_info.get_local_cache_dir()
            content_root = playstation.find_psv_content_root(cache_dir, title_id)
            if not content_root:
                logger.log_error("No Vita app content (sce_sys/param.sfo) for %s in '%s'" % (title_id, cache_dir))
                return False
            if not self.stage_workbin(cache_dir, content_root, verbose, pretend_run, exit_on_failure):
                logger.log_error("Could not stage work.bin for %s" % title_id)
                return False
            launch_cmd += [content_root]

        # Launch game
        return emulatorcommon.simple_launch(
            game_info = game_info,
            launch_cmd = launch_cmd,
            capture_type = capture_type,
            capture_file = capture_file,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
