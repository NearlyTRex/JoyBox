# Local imports
from joybox import config
from joybox import logger
from joybox import release
from joybox import sourcebuild
from joybox import programs
from joybox import toolbase


# PS3Dec tool
class PS3Dec(toolbase.ToolBase):

    NAME = "PS3Dec"

    # Windows exe from the NearlyTRex/PS3Dec GitHub release; Linux AppImage built from the
    # same repo with CMake and Ninja
    def setup(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Download windows program
        if programs.should_program_be_installed("PS3Dec", "windows"):
            success = release.download_github_release(
                github_user = "NearlyTRex",
                github_repo = "PS3Dec",
                starts_with = "PS3Dec",
                ends_with = ".zip",
                search_file = "PS3Dec.exe",
                install_name = "PS3Dec",
                install_dir = programs.get_program_install_dir("PS3Dec", "windows"),
                backups_dir = programs.get_program_backup_dir("PS3Dec", "windows"),
                install_files = ["PS3Dec.exe"],
                locker_type = setup_params.locker_type,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup PS3Dec")
                return False

        # Build linux program
        if programs.should_program_be_installed("PS3Dec", "linux"):
            success = sourcebuild.build_appimage_from_source(
                release_url = "https://github.com/NearlyTRex/PS3Dec.git",
                output_file = "App-x86_64.AppImage",
                install_name = "PS3Dec",
                install_dir = programs.get_program_install_dir("PS3Dec", "linux"),
                backups_dir = programs.get_program_backup_dir("PS3Dec", "linux"),
                build_cmd = [
                    "cmake", "-G", "Ninja", "..",
                    "&&",
                    "ninja"
                ],
                build_dir = "Build",
                internal_copies = [
                    {"from": "Source/PS3Dec/Build/Release/PS3Dec", "to": "AppImage/usr/bin/PS3Dec"},
                    {"from": "AppImageTool/linux/app.desktop", "to": "AppImage/app.desktop"},
                    {"from": "AppImageTool/linux/icon.svg", "to": "AppImage/icon.svg"}
                ],
                internal_symlinks = [
                    {"from": "usr/bin/PS3Dec", "to": "AppRun"}
                ],
                locker_type = setup_params.locker_type,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup PS3Dec")
                return False
        return True

    # Install the Windows and Linux builds from the releases stored in their backups dirs
    def setup_offline(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Setup windows program
        if programs.should_program_be_installed("PS3Dec", "windows"):
            success = release.setup_stored_release(
                archive_dir = programs.get_program_backup_dir("PS3Dec", "windows"),
                install_name = "PS3Dec",
                install_dir = programs.get_program_install_dir("PS3Dec", "windows"),
                search_file = "PS3Dec.exe",
                install_files = ["PS3Dec.exe"],
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup PS3Dec")
                return False

        # Setup linux program
        if programs.should_program_be_installed("PS3Dec", "linux"):
            success = release.setup_stored_release(
                archive_dir = programs.get_program_backup_dir("PS3Dec", "linux"),
                install_name = "PS3Dec",
                install_dir = programs.get_program_install_dir("PS3Dec", "linux"),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup PS3Dec")
                return False
        return True
