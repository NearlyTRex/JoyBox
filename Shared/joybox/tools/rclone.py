# Local imports
import joybox.config as config
import joybox.logger as logger
import joybox.paths as paths
import joybox.environment as environment
import joybox.fileops as fileops
import joybox.release as release
import joybox.programs as programs
import joybox.toolbase as toolbase

# What rclone.conf holds. The remotes are defined by the settings and reach
# rclone through the environment of each command; see joybox.rcloneremotes.
config_note = """# Written by JoyBox. Remotes come from the locker settings in JoyBox.ini at
# run time, so no credential is kept here; anything added here is replaced.
"""

# RClone tool
class RClone(toolbase.ToolBase):

    # Get name
    def get_name(self):
        return "RClone"

    # Get config
    def get_config(self):
        return {
            "RClone": {
                "program": {
                    "windows": "RClone/windows/rclone.exe",
                    "linux": "RClone/linux/rclone"
                },
                "config_file": {
                    "windows": "RClone/windows/rclone.conf",
                    "linux": "RClone/linux/rclone.conf"
                },
                "cache_dir": {
                    "windows": "RClone/windows/cache",
                    "linux": "RClone/linux/cache"
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
        if programs.should_program_be_installed("RClone", "windows"):
            success = release.download_general_release(
                archive_url = "https://downloads.rclone.org/rclone-current-windows-amd64.zip",
                search_file = "rclone.exe",
                install_name = "RClone",
                install_dir = programs.get_program_install_dir("RClone", "windows"),
                backups_dir = programs.get_program_backup_dir("RClone", "windows"),
                locker_type = setup_params.locker_type,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup RClone")
                return False

        # Download linux program
        if programs.should_program_be_installed("RClone", "linux"):
            success = release.download_general_release(
                archive_url = "https://downloads.rclone.org/rclone-current-linux-amd64.zip",
                search_file = "rclone",
                install_name = "RClone",
                install_dir = programs.get_program_install_dir("RClone", "linux"),
                backups_dir = programs.get_program_backup_dir("RClone", "linux"),
                locker_type = setup_params.locker_type,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup RClone")
                return False
        return True

    # Setup offline
    def setup_offline(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Setup windows program
        if programs.should_program_be_installed("RClone", "windows"):
            success = release.setup_stored_release(
                archive_dir = programs.get_program_backup_dir("RClone", "windows"),
                install_name = "RClone",
                install_dir = programs.get_program_install_dir("RClone", "windows"),
                search_file = "rclone.exe",
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup RClone")
                return False

        # Setup linux program
        if programs.should_program_be_installed("RClone", "linux"):
            success = release.setup_stored_release(
                archive_dir = programs.get_program_backup_dir("RClone", "linux"),
                install_name = "RClone",
                install_dir = programs.get_program_install_dir("RClone", "linux"),
                search_file = "rclone",
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup RClone")
                return False
        return True

    # Configure
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
                contents = config_note,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup RClone config files")
                return False
        return True
