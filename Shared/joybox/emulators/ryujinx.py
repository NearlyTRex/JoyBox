# Local imports
from joybox import config
from joybox import logger
from joybox import release
from joybox import programs
from joybox import emulatorbase

# Config files
config_files = {}
config_files["Ryujinx/windows/portable/Config.json"] = ""
config_files["Ryujinx/linux/portable/Config.json"] = ""

# System files
system_files = {}

# The release asset suffix and the file to find in it for each platform
RELEASE_ASSETS = {
    "windows": ("win_x64.zip", "Ryujinx.exe"),
    "linux": ("linux_x64.tar.gz", "Ryujinx.sh")
}

# Download the platform's build from the release-channel-master GitHub release; False, after logging, on failure
def download_platform_release(platform, setup_params):
    ends_with, search_file = RELEASE_ASSETS[platform]
    success = release.download_github_release(
        github_user = "Ryujinx",
        github_repo = "release-channel-master",
        starts_with = "ryujinx",
        ends_with = ends_with,
        search_file = search_file,
        install_name = "Ryujinx",
        install_dir = programs.get_program_install_dir("Ryujinx", platform),
        backups_dir = programs.get_program_backup_dir("Ryujinx", platform),
        locker_type = setup_params.locker_type,
        verbose = setup_params.verbose,
        pretend_run = setup_params.pretend_run,
        exit_on_failure = setup_params.exit_on_failure)
    if not success:
        logger.log_error("Could not setup Ryujinx")
        return False
    return True

# Ryujinx emulator
class Ryujinx(emulatorbase.EmulatorBase):

    NAME = "Ryujinx"

    # Get the files setup writes; Ryujinx is not registered, so they are kept here
    def get_config_files(self):
        return dict(config_files)

    # Get the system files setup checks
    def get_system_files(self):
        return dict(system_files)

    # Program paths fixed in code rather than read from program data, with sandboxing off on both platforms
    def get_config(self):
        return {
            "Ryujinx": {
                "program": {
                    "windows": "Ryujinx/windows/Ryujinx.exe",
                    "linux": "Ryujinx/linux/Ryujinx"
                },
                "run_sandboxed": {
                    "windows": False,
                    "linux": False
                }
            }
        }

    # Download the Windows zip and Linux tarball from the Ryujinx release-channel-master GitHub release
    def setup(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Download windows and linux programs
        for platform in ["windows", "linux"]:
            if programs.should_program_be_installed("Ryujinx", platform):
                if not download_platform_release(platform, setup_params):
                    return False
        return True

    # Install the Windows and Linux builds from the releases stored in their backups dirs
    def setup_offline(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Setup windows program
        if programs.should_program_be_installed("Ryujinx", "windows"):
            success = release.setup_stored_release(
                archive_dir = programs.get_program_backup_dir("Ryujinx", "windows"),
                install_name = "Ryujinx",
                install_dir = programs.get_program_install_dir("Ryujinx", "windows"),
                search_file = "Ryujinx.exe",
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup Ryujinx")
                return False

        # Setup linux program
        if programs.should_program_be_installed("Ryujinx", "linux"):
            success = release.setup_stored_release(
                archive_dir = programs.get_program_backup_dir("Ryujinx", "linux"),
                install_name = "Ryujinx",
                install_dir = programs.get_program_install_dir("Ryujinx", "linux"),
                search_file = "Ryujinx.sh",
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup Ryujinx")
                return False
        return True
