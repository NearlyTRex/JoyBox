# Imports
import os
import json
import string
import secrets
import hashlib

# Local imports
import joybox.config as config
import joybox.logger as logger
import joybox.paths as paths
import joybox.environment as environment
import joybox.fileops as fileops
import joybox.release as release
import joybox.programs as programs
import joybox.serialization as serialization
import joybox.toolbase as toolbase
import joybox.desktopentry as desktopentry
import joybox.settings as settings

# Config files
config_files = {}
config_files["Sunshine/windows/config/sunshine.conf"] = ""
config_files["Sunshine/linux/Sunshine.AppImage.home/.config/sunshine/sunshine.conf"] = ""
config_files["Sunshine/windows/config/apps.json"] = ""
config_files["Sunshine/linux/Sunshine.AppImage.home/.config/sunshine/apps.json"] = ""

# Build the app list a Moonlight client can start from, from config.streaming_apps
# The Linux AppImage runs with its .home folder as HOME, which its apps would
# inherit, so the real one is put back for them.
def build_apps(platform):
    apps = []
    for streaming_app in config.streaming_apps:
        app = {"name": streaming_app["name"]}
        if "command" in streaming_app:
            app["cmd"] = environment.get_command_path(streaming_app["command"])
        if "detached" in streaming_app:
            app["detached"] = [streaming_app["detached"][platform]]
        if "undo" in streaming_app:
            app["prep-cmd"] = [{"do": "", "undo": streaming_app["undo"][platform]}]
        if "image" in streaming_app:
            app["image-path"] = streaming_app["image"]
        apps.append(app)
    return json.dumps({
        "env": {"HOME": os.path.expanduser("~")} if platform == "linux" else {},
        "apps": apps
    }, indent = 4)

# Where each platform's Sunshine keeps its state: the web page login, and the
# clients paired with it, which writing the login must keep
state_files = {
    "windows": "Sunshine/windows/config/sunshine_state.json",
    "linux": "Sunshine/linux/Sunshine.AppImage.home/.config/sunshine/sunshine_state.json",
}

# What a login's salt is made of, and how long it is, as Sunshine makes them
salt_alphabet = string.ascii_letters + string.digits + "!@#$%^&*()"
salt_length = 16

# Hash a web page password the way Sunshine checks it: SHA-256 of the password
# followed by its salt, written as hex with the bytes in reverse order
def hash_password(password, salt):
    return hashlib.sha256((password + salt).encode("utf-8")).digest()[::-1].hex().upper()

# Check whether a state already holds this login
def is_login_current(state, username, password):
    return (state.get("username") == username and isinstance(state.get("salt"), str)
        and state.get("password") == hash_password(password, state["salt"]))

# Write the web page login into a state file, keeping everything else in it
def write_login(state_file, username, password, verbose = False, pretend_run = False, exit_on_failure = False):
    state = {}
    if paths.does_path_exist(state_file):
        try:
            state = json.loads(serialization.read_text_file(state_file) or "")
        except ValueError:
            state = None
        if not isinstance(state, dict):
            logger.log_error("Unable to read %s, so the Sunshine login is not written over it" % state_file)
            return False
    if is_login_current(state, username, password):
        return True
    salt = "".join(secrets.choice(salt_alphabet) for _ in range(salt_length))
    state.update({"username": username, "salt": salt, "password": hash_password(password, salt)})
    return fileops.touch_file(
        src = state_file,
        contents = json.dumps(state, indent = 4),
        private = True,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

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

        # Write the web page login, so the page never asks for one
        username = settings.get_value("UserData.Streaming", "sunshine_user", "", throw_exception = False)
        password = settings.get_value("UserData.Streaming", "sunshine_pass", "", throw_exception = False)
        if username and password:
            for state_file in state_files.values():
                success = write_login(
                    state_file = paths.join_paths(environment.get_tools_root_dir(), state_file),
                    username = username,
                    password = password,
                    verbose = setup_params.verbose,
                    pretend_run = setup_params.pretend_run,
                    exit_on_failure = setup_params.exit_on_failure)
                if not success:
                    logger.log_error("Could not setup the Sunshine login")
                    return False
        else:
            logger.log_info("No [UserData.Streaming] sunshine_user and sunshine_pass are set, so Sunshine's web page asks for a login")

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
