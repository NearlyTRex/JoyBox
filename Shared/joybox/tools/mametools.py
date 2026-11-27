# Local imports
from joybox import config
from joybox import logger
from joybox import release
from joybox import sourcebuild
from joybox import programs
from joybox import toolbase


# MameTools tool
class MameTools(toolbase.ToolBase):

    NAME = "MameTools"

    # Windows chdman.exe pulled from the mamedev/mame self-extracting release; Linux chdman AppImage
    # built tools-only from the NearlyTRex/Mame fork
    def setup(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Download windows program
        if programs.should_program_be_installed("MameChdman", "windows"):
            success = release.download_github_release(
                github_user = "mamedev",
                github_repo = "mame",
                starts_with = "mame",
                ends_with = "x64.exe",
                search_file = "chdman.exe",
                install_name = "MameChdman",
                install_dir = programs.get_program_install_dir("MameChdman", "windows"),
                backups_dir = programs.get_program_backup_dir("MameChdman", "windows"),
                install_files = ["chdman.exe"],
                release_type = config.ReleaseType.ARCHIVE,
                get_latest = True,
                locker_type = setup_params.locker_type,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup MameChdman")
                return False

        # Build linux program
        if programs.should_program_be_installed("MameChdman", "linux"):
            success = sourcebuild.build_appimage_from_source(
                release_url = "https://github.com/NearlyTRex/Mame.git",
                output_file = "App-x86_64.AppImage",
                install_name = "MameChdman",
                install_dir = programs.get_program_install_dir("MameChdman", "linux"),
                backups_dir = programs.get_program_backup_dir("MameChdman", "linux"),
                build_cmd = [
                    "make", "TOOLS=1", "EMULATOR=0", "-j5"
                ],
                internal_copies = [
                    {"from": "Source/Mame/chdman", "to": "AppImage/usr/bin/chdman"},
                    {"from": "AppImageTool/linux/app.desktop", "to": "AppImage/app.desktop"},
                    {"from": "AppImageTool/linux/icon.svg", "to": "AppImage/icon.svg"}
                ],
                internal_symlinks = [
                    {"from": "usr/bin/chdman", "to": "AppRun"}
                ],
                locker_type = setup_params.locker_type,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup MameChdman")
                return False
        return True

    # Install chdman for Windows and Linux from the releases stored in their backups dirs
    def setup_offline(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Setup windows program
        if programs.should_program_be_installed("MameChdman", "windows"):
            success = release.setup_stored_release(
                archive_dir = programs.get_program_backup_dir("MameChdman", "windows"),
                install_name = "MameChdman",
                install_dir = programs.get_program_install_dir("MameChdman", "windows"),
                search_file = "chdman.exe",
                install_files = ["chdman.exe"],
                release_type = config.ReleaseType.ARCHIVE,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup MameChdman")
                return False

        # Setup linux program
        if programs.should_program_be_installed("MameChdman", "linux"):
            success = release.setup_stored_release(
                archive_dir = programs.get_program_backup_dir("MameChdman", "linux"),
                install_name = "MameChdman",
                install_dir = programs.get_program_install_dir("MameChdman", "linux"),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup MameChdman")
                return False
        return True
