# Imports
import os
import os.path

# Local imports
from joybox import config
from joybox import environment
from joybox import fileops
from joybox import logger
from joybox import paths
from joybox import programs
from joybox import archive
from joybox import playstation
from joybox import emulatorcommon
from joybox import emulatorbase

# Unzip the locker's os0, sa0 or vs0 archive into the platform's setup dir, keeping files
# already there; True when the locker has no such archive
def extract_system_archive(platform, obj, setup_params):
    if not os.path.exists(paths.join_paths(environment.get_locker_gaming_emulator_setup_dir("Vita3K"), obj + config.ArchiveFileType.ZIP.cval())):
        return True
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

# Vita3K emulator
class Vita3K(emulatorbase.EmulatorBase):

    NAME = "Vita3K"

    # Write its config files, verify the locker system files, then unzip the os0, sa0 and vs0 archives
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
                logger.log_error("Could not setup Vita3K config files")
                return False

        # Verify system files
        if not self.verify_system_files(self.get_system_files(), setup_params):
            return False

        # Extract system files
        for platform in ["windows", "linux"]:
            for obj in ["os0", "sa0", "vs0"]:
                if not extract_system_archive(platform, obj, setup_params):
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

    # The cached game's Vita app content root with its work.bin staged; None, after
    # logging, when there is no content or staging fails
    def stage_cached_content(self, game_info, title_id, verbose, pretend_run, exit_on_failure):
        cache_dir = game_info.get_local_cache_dir()
        content_root = playstation.find_psv_content_root(cache_dir, title_id)
        if not content_root:
            logger.log_error("No Vita app content (sce_sys/param.sfo) for %s in '%s'" % (title_id, cache_dir))
            return None
        if not self.stage_workbin(cache_dir, content_root, verbose, pretend_run, exit_on_failure):
            logger.log_error("Could not stage work.bin for %s" % title_id)
            return None
        return content_root

    # The arguments that run the game: its title id when the app is installed, else its
    # staged cached content; None when the content cannot be staged
    def get_game_args(self, game_info, title_id, verbose, pretend_run, exit_on_failure):

        # Run installed app
        if os.path.isdir(paths.join_paths(programs.get_emulator_path_config_value("Vita3K", "app_dir"), title_id)):
            return ["-r", config.TOKEN_GAME_NAME]

        # Install and run from the cache
        content_root = self.stage_cached_content(game_info, title_id, verbose, pretend_run, exit_on_failure)
        if not content_root:
            return None
        return [content_root]

    # Run Vita3K by title id when the app is installed, else stage the cached content and run it from there;
    # False when the game has no title id as its launch name
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

        # Add the installed app or the staged cached content
        game_args = self.get_game_args(game_info, title_id, verbose, pretend_run, exit_on_failure)
        if game_args is None:
            return False
        launch_cmd += game_args

        # Launch game
        return emulatorcommon.simple_launch(
            game_info = game_info,
            launch_cmd = launch_cmd,
            capture_type = capture_type,
            capture_file = capture_file,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
