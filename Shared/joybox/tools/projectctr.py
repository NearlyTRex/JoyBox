# Local imports
from joybox import config
from joybox import logger
from joybox import release
from joybox import programs
from joybox import toolbase


# ProjectCTR tool
class ProjectCTR(toolbase.ToolBase):

    NAME = "ProjectCTR"

    # Download makerom and ctrtool for Windows and Linux from the 3DSGuy/Project_CTR GitHub release,
    # marking the Linux ones executable
    def setup(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Download windows program
        if programs.should_program_be_installed("CtrMakeRom", "windows"):
            success = release.download_github_release(
                github_user = "3DSGuy",
                github_repo = "Project_CTR",
                starts_with = "makerom",
                ends_with = "win_x86_64.zip",
                search_file = "makerom.exe",
                install_name = "CtrMakeRom",
                install_dir = programs.get_program_install_dir("CtrMakeRom", "windows"),
                backups_dir = programs.get_program_backup_dir("CtrMakeRom", "windows"),
                install_files = ["makerom.exe"],
                locker_type = setup_params.locker_type,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup CtrMakeRom")
                return False

        # Download windows program
        if programs.should_program_be_installed("CtrTool", "windows"):
            success = release.download_github_release(
                github_user = "3DSGuy",
                github_repo = "Project_CTR",
                starts_with = "ctrtool",
                ends_with = "win_x64.zip",
                search_file = "ctrtool.exe",
                install_name = "CtrTool",
                install_dir = programs.get_program_install_dir("CtrTool", "windows"),
                backups_dir = programs.get_program_backup_dir("CtrTool", "windows"),
                install_files = ["ctrtool.exe"],
                locker_type = setup_params.locker_type,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup CtrTool")
                return False

        # Download linux program
        if programs.should_program_be_installed("CtrMakeRom", "linux"):
            success = release.download_github_release(
                github_user = "3DSGuy",
                github_repo = "Project_CTR",
                starts_with = "makerom",
                ends_with = "ubuntu_x86_64.zip",
                search_file = "makerom",
                install_name = "CtrMakeRom",
                install_dir = programs.get_program_install_dir("CtrMakeRom", "linux"),
                backups_dir = programs.get_program_backup_dir("CtrMakeRom", "linux"),
                install_files = ["makerom"],
                release_type = config.ReleaseType.ARCHIVE,
                chmod_files = [
                    {
                        "file": "makerom",
                        "perms": 755
                    }
                ],
                locker_type = setup_params.locker_type,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup CtrMakeRom")
                return False

        # Download linux program
        if programs.should_program_be_installed("CtrTool", "linux"):
            success = release.download_github_release(
                github_user = "3DSGuy",
                github_repo = "Project_CTR",
                starts_with = "ctrtool",
                ends_with = "ubuntu_x86_64.zip",
                search_file = "ctrtool",
                install_name = "CtrTool",
                install_dir = programs.get_program_install_dir("CtrTool", "linux"),
                backups_dir = programs.get_program_backup_dir("CtrTool", "linux"),
                install_files = ["ctrtool"],
                release_type = config.ReleaseType.ARCHIVE,
                chmod_files = [
                    {
                        "file": "ctrtool",
                        "perms": 755
                    }
                ],
                locker_type = setup_params.locker_type,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup CtrTool")
                return False
        return True

    # Install makerom and ctrtool for Windows and Linux from the releases stored in their backups dirs
    def setup_offline(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Setup windows program
        if programs.should_program_be_installed("CtrMakeRom", "windows"):
            success = release.setup_stored_release(
                archive_dir = programs.get_program_backup_dir("CtrMakeRom", "windows"),
                install_name = "CtrMakeRom",
                install_dir = programs.get_program_install_dir("CtrMakeRom", "windows"),
                search_file = "makerom.exe",
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup CtrMakeRom")
                return False

        # Setup windows program
        if programs.should_program_be_installed("CtrTool", "windows"):
            success = release.setup_stored_release(
                archive_dir = programs.get_program_backup_dir("CtrTool", "windows"),
                install_name = "CtrTool",
                install_dir = programs.get_program_install_dir("CtrTool", "windows"),
                search_file = "ctrtool.exe",
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup CtrTool")
                return False

        # Setup linux program
        if programs.should_program_be_installed("CtrMakeRom", "linux"):
            success = release.setup_stored_release(
                archive_dir = programs.get_program_backup_dir("CtrMakeRom", "linux"),
                install_name = "CtrMakeRom",
                install_dir = programs.get_program_install_dir("CtrMakeRom", "linux"),
                search_file = "makerom",
                install_files = ["makerom"],
                release_type = config.ReleaseType.ARCHIVE,
                chmod_files = [
                    {
                        "file": "makerom",
                        "perms": 755
                    }
                ],
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup CtrMakeRom")
                return False

        # Setup linux program
        if programs.should_program_be_installed("CtrTool", "linux"):
            success = release.setup_stored_release(
                archive_dir = programs.get_program_backup_dir("CtrTool", "linux"),
                install_name = "CtrTool",
                install_dir = programs.get_program_install_dir("CtrTool", "linux"),
                search_file = "ctrtool",
                install_files = ["ctrtool"],
                release_type = config.ReleaseType.ARCHIVE,
                chmod_files = [
                    {
                        "file": "ctrtool",
                        "perms": 755
                    }
                ],
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup CtrTool")
                return False
        return True
