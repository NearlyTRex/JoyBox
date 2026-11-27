# Local imports
from joybox import config
from joybox import fileops
from joybox import filebulk
from joybox import logger
from joybox import paths
from joybox import release
from joybox import programs
from joybox import toolbase


# Files under the GoldbergEmu lib dir whose names end with an entry of the given tool config list
def get_libs(key):
    lib_files = []
    lib_root = programs.get_library_install_dir("GoldbergEmu", "lib")
    for potential_file in paths.build_file_list(lib_root):
        for lib_file in programs.get_tool_config_value("GoldbergEmu", key):
            if potential_file.endswith(lib_file):
                lib_files.append(potential_file)
    return lib_files

# Get 32-bit libs
def get_libs32():
    return get_libs("lib32")

# Get 64-bit libs
def get_libs64():
    return get_libs("lib64")

# The Goldberg SteamEmu Saves dir under a prefix's roaming AppData
def generate_base_path(prefix_dir):
    return paths.join_paths(prefix_dir, "AppData", "Roaming", "Goldberg SteamEmu Saves")

# Generate username file path
def generate_username_file(prefix_dir):
    return paths.join_paths(generate_base_path(prefix_dir), "settings", "account_name.txt")

# Generate userid file path
def generate_userid_file(prefix_dir):
    return paths.join_paths(generate_base_path(prefix_dir), "settings", "user_steam_id.txt")

# Rewrite a path in the Steam userdata dir for a user to the matching Goldberg saves path
def convert_from_native_path(path, user_id):
    src_path = paths.join_paths(config.COMPUTER_FOLDER_STORE, config.StoreType.STEAM, "userdata", user_id)
    dest_path = paths.join_paths(config.COMPUTER_FOLDER_APPDATA, "Roaming", "Goldberg SteamEmu Saves")
    return path.replace(src_path, dest_path)

# Rewrite a path in the Goldberg saves dir to the matching Steam userdata path for a user
def convert_to_native_path(path, user_id):
    src_path = paths.join_paths(config.COMPUTER_FOLDER_APPDATA, "Roaming", "Goldberg SteamEmu Saves")
    dest_path = paths.join_paths(config.COMPUTER_FOLDER_STORE, config.StoreType.STEAM, "userdata", user_id)
    return path.replace(src_path, dest_path)

# Write the account name and Steam id files Goldberg reads from a prefix's settings dir
def setup_user_files(
    prefix_dir,
    user_name,
    user_id,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Create username file
    success = fileops.touch_file(
        src = generate_username_file(prefix_dir),
        contents = "%s\n" % user_name,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return False

    # Create userid file
    success = fileops.touch_file(
        src = generate_userid_file(prefix_dir),
        contents = "%s\n" % user_id,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return False

    # Must have succeeded
    return True

# Move Goldberg save files in a save dir, minus its settings, into the Steam userdata layout,
# then remove the emptied Goldberg and roaming dirs
def convert_to_native_save(
    save_dir,
    user_id,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get relative paths
    roaming_path = paths.join_paths(config.SaveType.GENERAL, config.COMPUTER_FOLDER_APPDATA, "Roaming")
    search_path = paths.join_paths(config.SaveType.GENERAL, config.COMPUTER_FOLDER_APPDATA, "Roaming", "Goldberg SteamEmu Saves")
    ignore_path = paths.join_paths(config.SaveType.GENERAL, config.COMPUTER_FOLDER_APPDATA, "Roaming", "Goldberg SteamEmu Saves", "settings")
    replace_path = paths.join_paths(config.SaveType.GENERAL, config.COMPUTER_FOLDER_STORE, config.StoreType.STEAM, "userdata", user_id)

    # Move save files
    for save_file in paths.build_file_list(save_dir):
        if search_path in save_file and ignore_path not in save_file:
            success = filebulk.smart_move(
                src = save_file,
                dest = save_file.replace(search_path, replace_path),
                show_progress = True,
                skip_existing = False,
                skip_identical = False,
                case_sensitive_paths = True,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                return False

    # Clean search path
    full_search_path = paths.join_paths(save_dir, search_path)
    success = fileops.remove_directory(
        src = full_search_path,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return False

    # Clean roaming dir
    full_roaming_path = paths.join_paths(save_dir, roaming_path)
    if not paths.does_directory_contain_files(full_roaming_path):
        success = fileops.remove_directory(
            src = full_roaming_path,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return False

    # Should be successful
    return True

# GoldbergEmu tool
class GoldbergEmu(toolbase.ToolBase):

    NAME = "GoldbergEmu"

    # Download the latest GitLab job artifact linked from the Goldberg emulator page into its lib dir
    def setup(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Download library
        if programs.should_library_be_installed("GoldbergEmu"):
            success = release.download_webpage_release(
                webpage_url = "https://mr_goldberg.gitlab.io/goldberg_emulator/",
                webpage_base_url = "https://gitlab.com",
                starts_with = "https://gitlab.com/Mr_Goldberg/goldberg_emulator/-/jobs/",
                ends_with = "/artifacts/download",
                install_name = "GoldbergEmu",
                install_dir = programs.get_library_install_dir("GoldbergEmu", "lib"),
                backups_dir = programs.get_library_backup_dir("GoldbergEmu", "lib"),
                locker_type = setup_params.locker_type,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup GoldbergEmu")
                return False
        return True

    # Install the library from the release stored in its backups dir
    def setup_offline(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Setup library
        if programs.should_library_be_installed("GoldbergEmu"):
            success = release.setup_stored_release(
                archive_dir = programs.get_library_backup_dir("GoldbergEmu", "lib"),
                install_name = "GoldbergEmu",
                install_dir = programs.get_library_install_dir("GoldbergEmu", "lib"),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup GoldbergEmu")
                return False
        return True
