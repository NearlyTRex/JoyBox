# Imports
import os
import os.path

# Local imports
from joybox import config
from joybox import fileops
from joybox import logger
from joybox import paths
from joybox import programs
from joybox import playstation
from joybox import emulatorbase

# Vita3K emulator
class Vita3K(emulatorbase.EmulatorBase):

    NAME = "Vita3K"

    SYSTEM_ARCHIVES = ("os0", "sa0", "vs0")

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

    # Whether the app with the title id is already installed in Vita3K's app dir
    def is_app_installed(self, title_id):
        return os.path.isdir(paths.join_paths(programs.get_emulator_path_config_value("Vita3K", "app_dir"), title_id))

    # Stage the cached content when its app is not installed; False, after logging, when the
    # game has no title id as its launch name or its content cannot be staged
    def prepare_launch(self, game_info, verbose = False, pretend_run = False, exit_on_failure = False):
        title_id = game_info.get_launch_name()
        if not title_id:
            logger.log_error("Vita3K needs the game's title id as its launch name")
            return False
        if self.is_app_installed(title_id):
            return True
        return self.stage_cached_content(game_info, title_id, verbose, pretend_run, exit_on_failure) is not None

    # Run Vita3K by title id when the app is installed, else on the cached content root
    def get_launch_command(self, game_info, fullscreen = False):
        title_id = game_info.get_launch_name()
        launch_cmd = [programs.get_emulator_program("Vita3K")]
        if fullscreen:
            launch_cmd += ["-F"]
        if self.is_app_installed(title_id):
            return launch_cmd + ["-r", config.TOKEN_GAME_NAME]
        return launch_cmd + [playstation.find_psv_content_root(game_info.get_local_cache_dir(), title_id)]
