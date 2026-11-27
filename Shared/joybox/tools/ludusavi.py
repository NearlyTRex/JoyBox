# Local imports
from joybox import config
from joybox import logger
from joybox import paths
from joybox import release
from joybox import programs
from joybox import environment
from joybox import fileops
from joybox import toolbase


# Ludusavi tool
class Ludusavi(toolbase.ToolBase):

    # Get name
    def get_name(self):
        return "Ludusavi"

    # Setup
    def setup(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Download windows program
        if programs.should_program_be_installed("Ludusavi", "windows"):
            success = release.download_github_release(
                github_user = "mtkennerly",
                github_repo = "ludusavi",
                starts_with = "ludusavi",
                ends_with = "win64.zip",
                search_file = "ludusavi.exe",
                install_name = "Ludusavi",
                install_dir = programs.get_program_install_dir("Ludusavi", "windows"),
                backups_dir = programs.get_program_backup_dir("Ludusavi", "windows"),
                install_files = ["ludusavi.exe"],
                locker_type = setup_params.locker_type,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup Ludusavi")
                return False

        # Download linux program
        if programs.should_program_be_installed("Ludusavi", "linux"):
            success = release.download_github_release(
                github_user = "mtkennerly",
                github_repo = "ludusavi",
                starts_with = "ludusavi",
                ends_with = "linux.zip",
                search_file = "ludusavi",
                install_name = "Ludusavi",
                install_dir = programs.get_program_install_dir("Ludusavi", "linux"),
                backups_dir = programs.get_program_backup_dir("Ludusavi", "linux"),
                install_files = ["ludusavi"],
                chmod_files = [
                    {
                        "file": "ludusavi",
                        "perms": 755
                    }
                ],
                locker_type = setup_params.locker_type,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup Ludusavi")
                return False
        return True

    # Setup offline
    def setup_offline(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Setup windows program
        if programs.should_program_be_installed("Ludusavi", "windows"):
            success = release.setup_stored_release(
                archive_dir = programs.get_program_backup_dir("Ludusavi", "windows"),
                install_name = "Ludusavi",
                install_dir = programs.get_program_install_dir("Ludusavi", "windows"),
                search_file = "ludusavi.exe",
                install_files = ["ludusavi.exe"],
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup Ludusavi")
                return False

        # Setup linux program
        if programs.should_program_be_installed("Ludusavi", "linux"):
            success = release.setup_stored_release(
                archive_dir = programs.get_program_backup_dir("Ludusavi", "linux"),
                install_name = "Ludusavi",
                install_dir = programs.get_program_install_dir("Ludusavi", "linux"),
                search_file = "ludusavi",
                install_files = ["ludusavi"],
                chmod_files = [
                    {
                        "file": "ludusavi",
                        "perms": 755
                    }
                ],
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup Ludusavi")
                return False
        return True

    # Configure
    def configure(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Create config files
        for config_filename, config_contents in self.get_config_files().items():
            success = fileops.touch_file(
                src = paths.join_paths(environment.get_tools_root_dir(), config_filename),
                contents = config_contents.strip(),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup Ludusavi config files")
                return False
        return True
