# Local imports
from joybox import config
from joybox import logger
from joybox import paths
from joybox import environment
from joybox import fileops
from joybox import toolbase
from joybox import platform_info


# LGOGDownloader tool
class LGOGDownloader(toolbase.ToolBase):

    NAME = "LGOGDownloader"

    # On Linux, write its config files under the tools root
    def configure(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Create config files
        if platform_info.is_linux_platform():
            for config_filename, config_contents in self.get_config_files().items():
                success = fileops.touch_file(
                    src = paths.join_paths(environment.get_tools_root_dir(), config_filename),
                    contents = config_contents.strip(),
                    verbose = setup_params.verbose,
                    pretend_run = setup_params.pretend_run,
                    exit_on_failure = setup_params.exit_on_failure)
                if not success:
                    logger.log_error("Could not setup LGOGDownloader config files")
                    return False
        return True
