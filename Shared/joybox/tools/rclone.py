# Local imports
from joybox import config
from joybox import logger
from joybox import paths
from joybox import environment
from joybox import fileops
from joybox import toolbase

# What rclone.conf holds. The remotes are defined by the settings and reach
# rclone through the environment of each command; see joybox.rcloneremotes.
CONFIG_NOTE = """# Written by JoyBox. Remotes come from the locker settings in JoyBox.ini at
# run time, so no credential is kept here; anything added here is replaced.
"""

# RClone tool
class RClone(toolbase.ToolBase):

    NAME = "RClone"

    # Overwrite both rclone.conf files with a credential-free note, since remotes reach rclone
    # through each command's environment
    def configure(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Leave no credential behind from a config an earlier version wrote
        config_files = [
            "RClone/windows/rclone.conf",
            "RClone/linux/rclone.conf"
        ]
        for config_filename in config_files:
            success = fileops.touch_file(
                src = paths.join_paths(environment.get_tools_root_dir(), config_filename),
                contents = CONFIG_NOTE,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup RClone config files")
                return False
        return True
