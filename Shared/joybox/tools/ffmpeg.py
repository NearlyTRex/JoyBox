# Local imports
from joybox import config
from joybox import logger
from joybox import release
from joybox import programs
from joybox import toolbase


# FFMpeg tool
class FFMpeg(toolbase.ToolBase):

    NAME = "FFMpeg"

    # Download the ffmpeg binary for Windows and Linux from the BtbN/FFmpeg-Builds master GPL release
    def setup(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Download windows program
        if programs.should_program_be_installed("FFMpeg", "windows"):
            success = release.download_github_release(
                github_user = "BtbN",
                github_repo = "FFmpeg-Builds",
                starts_with = "ffmpeg-master-latest",
                ends_with = "win64-gpl.zip",
                search_file = "ffmpeg.exe",
                install_name = "FFMpeg",
                install_dir = programs.get_program_install_dir("FFMpeg", "windows"),
                backups_dir = programs.get_program_backup_dir("FFMpeg", "windows"),
                install_files = ["ffmpeg.exe"],
                locker_type = setup_params.locker_type,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup FFMpeg")
                return False

        # Download linux program
        if programs.should_program_be_installed("FFMpeg", "linux"):
            success = release.download_github_release(
                github_user = "BtbN",
                github_repo = "FFmpeg-Builds",
                starts_with = "ffmpeg-master-latest",
                ends_with = "linux64-gpl.tar.xz",
                search_file = "ffmpeg",
                install_name = "FFMpeg",
                install_dir = programs.get_program_install_dir("FFMpeg", "linux"),
                backups_dir = programs.get_program_backup_dir("FFMpeg", "linux"),
                install_files = ["ffmpeg"],
                locker_type = setup_params.locker_type,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup FFMpeg")
                return False
        return True

    # Install the Windows and Linux binaries from the releases stored in their backups dirs
    def setup_offline(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Setup windows program
        if programs.should_program_be_installed("FFMpeg", "windows"):
            success = release.setup_stored_release(
                archive_dir = programs.get_program_backup_dir("FFMpeg", "windows"),
                install_name = "FFMpeg",
                install_dir = programs.get_program_install_dir("FFMpeg", "windows"),
                search_file = "ffmpeg.exe",
                install_files = ["ffmpeg.exe"],
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup FFMpeg")
                return False

        # Setup linux program
        if programs.should_program_be_installed("FFMpeg", "linux"):
            success = release.setup_stored_release(
                archive_dir = programs.get_program_backup_dir("FFMpeg", "linux"),
                install_name = "FFMpeg",
                install_dir = programs.get_program_install_dir("FFMpeg", "linux"),
                search_file = "ffmpeg",
                install_files = ["ffmpeg"],
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup FFMpeg")
                return False
        return True
