# Imports
import os
import json

# Local imports
import joybox.config as config
import joybox.logger as logger
import joybox.paths as paths
import joybox.environment as environment
import joybox.fileops as fileops
import joybox.release as release
import joybox.programs as programs
import joybox.toolbase as toolbase
import joybox.desktopentry as desktopentry
import joybox.settings as settings

# Config files
config_files = {}
config_files["Sunshine/windows/config/sunshine.conf"] = ""
config_files["Sunshine/linux/Sunshine.AppImage.home/.config/sunshine/sunshine.conf"] = ""
config_files["Sunshine/windows/config/apps.json"] = ""
config_files["Sunshine/linux/Sunshine.AppImage.home/.config/sunshine/apps.json"] = ""

# Build the apps a Moonlight client can start
# The Linux AppImage runs with its .home folder as HOME, which its apps would
# inherit, so the real one is put back for them.
def build_apps(platform):
    steam_prefix = "setsid steam " if platform == "linux" else ""
    apps = {
        "env": {"HOME": os.path.expanduser("~")} if platform == "linux" else {},
        "apps": [
            {
                "name": "Desktop",
                "image-path": "desktop.png"
            },
            {
                "name": "Pegasus",
                "cmd": environment.get_command_path("launch_pegasus")
            },
            {
                "name": "Steam Big Picture",
                "detached": [steam_prefix + "steam://open/bigpicture"],
                "prep-cmd": [{"do": "", "undo": steam_prefix + "steam://close/bigpicture"}],
                "image-path": "steam.png"
            }
        ]
    }
    return json.dumps(apps, indent = 4)

# Sunshine tool
class Sunshine(toolbase.ToolBase):

    # Get name
    def get_name(self):
        return "Sunshine"

    # Get config
    def get_config(self):
        return {
            "Sunshine": {
                "program": {
                    "windows": "Sunshine/windows/sunshine.exe",
                    "linux": "Sunshine/linux/Sunshine.AppImage"
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
        if programs.should_program_be_installed("Sunshine", "windows"):
            success = release.download_github_release(
                github_user = "LizardByte",
                github_repo = "Sunshine",
                starts_with = "sunshine",
                ends_with = "windows.zip",
                search_file = "sunshine.exe",
                install_name = "Sunshine",
                install_dir = programs.get_program_install_dir("Sunshine", "windows"),
                backups_dir = programs.get_program_backup_dir("Sunshine", "windows"),
                install_files = ["sunshine.exe", "assets", "scripts", "tools"],
                locker_type = setup_params.locker_type,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup Sunshine")
                return False

        # Download linux program
        if programs.should_program_be_installed("Sunshine", "linux"):
            success = release.download_github_release(
                github_user = "LizardByte",
                github_repo = "Sunshine",
                starts_with = "sunshine",
                ends_with = ".AppImage",
                search_file = "Sunshine.AppImage",
                install_name = "Sunshine",
                install_dir = programs.get_program_install_dir("Sunshine", "linux"),
                backups_dir = programs.get_program_backup_dir("Sunshine", "linux"),
                locker_type = setup_params.locker_type,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup Sunshine")
                return False
        return True

    # Setup offline
    def setup_offline(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Setup windows program
        if programs.should_program_be_installed("Sunshine", "windows"):
            success = release.setup_stored_release(
                archive_dir = programs.get_program_backup_dir("Sunshine", "windows"),
                install_name = "Sunshine",
                install_dir = programs.get_program_install_dir("Sunshine", "windows"),
                search_file = "sunshine.exe",
                install_files = ["sunshine.exe", "assets", "scripts", "tools"],
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup Sunshine")
                return False

        # Setup linux program
        if programs.should_program_be_installed("Sunshine", "linux"):
            success = release.setup_stored_release(
                archive_dir = programs.get_program_backup_dir("Sunshine", "linux"),
                install_name = "Sunshine",
                install_dir = programs.get_program_install_dir("Sunshine", "linux"),
                search_file = "Sunshine.AppImage",
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup Sunshine")
                return False
        return True

    # Configure
    def configure(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Update app lists
        config_files["Sunshine/windows/config/apps.json"] = build_apps("windows")
        config_files["Sunshine/linux/Sunshine.AppImage.home/.config/sunshine/apps.json"] = build_apps("linux")

        # Create config files
        for config_filename, config_contents in config_files.items():
            success = fileops.touch_file(
                src = paths.join_paths(environment.get_tools_root_dir(), config_filename),
                contents = config_contents.strip(),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup Sunshine config files")
                return False

        # Put it in the app menu on a machine whose streaming role uses it
        success = desktopentry.set_launcher(
            enabled = settings.get_bool_value("Tools.Sunshine", "sunshine_streaming_host", False, throw_exception = False),
            filename = "joybox-sunshine.desktop",
            name = "Sunshine",
            description = "Stream this machine's games to Moonlight clients",
            command = "launch_sunshine",
            icon = "video-display",
            verbose = setup_params.verbose,
            pretend_run = setup_params.pretend_run,
            exit_on_failure = setup_params.exit_on_failure)
        if not success:
            logger.log_error("Could not setup the Sunshine launcher")
            return False
        return True
