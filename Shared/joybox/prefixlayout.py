# Where a Wine or Sandboxie prefix keeps things: its folder, its drives, its
# user and public profiles, and which of them a path falls under. Read only
# from the options and tool settings, so command options can use it.

# Imports
import copy
import getpass

# Local imports
from joybox import config
from joybox import paths
from joybox import platform_info
from joybox import programs
from joybox import validation

# Folder for the options' prefix name under the Wine sandbox_dir tool setting
def get_wine_prefix(options):
    return paths.join_paths(programs.get_tool_path_config_value("Wine", "sandbox_dir"), options.get_prefix_name())

# Folder for the options' prefix name under the Sandboxie sandbox_dir tool setting
def get_sandboxie_prefix(options):
    return paths.join_paths(programs.get_tool_path_config_value("Sandboxie", "sandbox_dir"), options.get_prefix_name())

# Wine or Sandboxie folder for the options' prefix name; None without a name or prefix kind
def get_prefix(options):
    prefix_dir = None
    if options.get_prefix_name():
        if options.is_wine_prefix():
            prefix_dir = get_wine_prefix(options)
        elif options.is_sandboxie_prefix():
            prefix_dir = get_sandboxie_prefix(options)
    return prefix_dir

# Host folder backing a Wine drive letter: drive_c for C, dosdevices/<letter>: for the rest
def get_wine_real_drive_path(options, drive):
    if drive.lower() == "c":
        return paths.join_paths(options.get_prefix_dir(), "drive_c")
    return paths.join_paths(options.get_prefix_dir(), "dosdevices", drive.lower() + ":")

# Host folder backing a Sandboxie drive letter, drive/<LETTER> in the prefix
def get_sandboxie_real_drive_path(options, drive):
    return paths.join_paths(options.get_prefix_dir(), "drive", drive.upper())

# Host folder backing a drive letter in the Wine or Sandboxie prefix; None when neither
def get_real_drive_path(options, drive):
    real_drive_path = None
    if options.is_wine_prefix():
        real_drive_path = get_wine_real_drive_path(options, drive)
    elif options.is_sandboxie_prefix():
        real_drive_path = get_sandboxie_real_drive_path(options, drive)
    return real_drive_path

# Host folder backing the prefix's C drive; None when it is neither Wine nor Sandboxie
def get_real_c_drive_path(options):
    return get_real_drive_path(options, "c")

# Host folder of the current user's profile in a Wine prefix, drive_c/users/<user>
def get_wine_user_profile_path(options):
    return paths.normalize_file_path(paths.join_paths(options.get_prefix_dir(), "drive_c", "users", getpass.getuser()))

# Host folder of the current user's profile in a Sandboxie prefix, user/current
def get_sandboxie_user_profile_path(options):
    return paths.normalize_file_path(paths.join_paths(options.get_prefix_dir(), "user", "current"))

# Host folder of the current user's profile in the Wine or Sandboxie prefix; None when neither
def get_user_profile_path(options):
    user_profile_dir = None
    if options.is_wine_prefix():
        user_profile_dir = get_wine_user_profile_path(options)
    elif options.is_sandboxie_prefix():
        user_profile_dir = get_sandboxie_user_profile_path(options)
    return user_profile_dir

# Host folder of the shared Public profile in a Wine prefix, drive_c/users/Public
def get_wine_public_profile_path(options):
    return paths.normalize_file_path(paths.join_paths(options.get_prefix_dir(), "drive_c", "users", "Public"))

# Host folder of the shared Public profile in a Sandboxie prefix, drive/C/Users/Public
def get_sandboxie_public_profile_path(options):
    return paths.normalize_file_path(paths.join_paths(options.get_prefix_dir(), "drive", "C", "Users", "Public"))

# Host folder of the Public profile in the Wine or Sandboxie prefix; None when neither
def get_public_profile_path(options):
    public_profile_dir = None
    if options.is_wine_prefix():
        public_profile_dir = get_wine_public_profile_path(options)
    elif options.is_sandboxie_prefix():
        public_profile_dir = get_sandboxie_public_profile_path(options)
    return public_profile_dir

# Disc token whose disc name appears in the disc file, else the main disc root token
def get_disc_token(disc_file):
    for disc_token, disc_name in config.token_disc_names.items():
        if disc_name in disc_file:
            return disc_token
    return config.TOKEN_DISC_MAIN_ROOT

# Map each disc's token to its drive letter in order, its path under disc_base_dir, or its bare name;
# discs past the last free drive letter fall back to the path
def add_disc_tokens(token_map, disc_files, disc_base_dir, use_drive_letters):
    for disc_letter_index, disc_file in enumerate(disc_files):

        # Get file basename
        disc_file_basename = paths.get_filename_basename(disc_file)

        # Find which token to use
        disc_token_to_use = get_disc_token(disc_file)

        # Add entry
        if use_drive_letters and disc_letter_index < len(config.drives_regular):
            token_map[disc_token_to_use] = "%s:/" % config.drives_regular[disc_letter_index]
        elif disc_base_dir:
            token_map[disc_token_to_use] = paths.join_paths(disc_base_dir, disc_file_basename)
        else:
            token_map[disc_token_to_use] = disc_file_basename

# Map path tokens to install, setup, hdd and per-disc roots; discs get drive letters in order when use_drive_letters is set
def build_token_map(
    store_install_dir = None,
    game_install_dir = None,
    setup_base_dir = None,
    hdd_base_dir = None,
    disc_base_dir = None,
    disc_files = (),
    use_drive_letters = False):

    # Create token map
    token_map = {}

    # Add paths
    if store_install_dir:
        token_map[config.TOKEN_STORE_INSTALL_DIR] = store_install_dir
    if game_install_dir:
        token_map[config.TOKEN_GAME_INSTALL_DIR] = game_install_dir
    if setup_base_dir:
        token_map[config.TOKEN_SETUP_MAIN_ROOT] = setup_base_dir
    if hdd_base_dir:
        token_map[config.TOKEN_HDD_MAIN_ROOT] = hdd_base_dir
        token_map[config.TOKEN_DOS_MAIN_ROOT] = paths.join_paths(hdd_base_dir, config.COMPUTER_FOLDER_DOS)
        token_map[config.TOKEN_SCUMM_MAIN_ROOT] = paths.join_paths(hdd_base_dir, config.COMPUTER_FOLDER_SCUMM)

    # Add discs
    add_disc_tokens(token_map, disc_files, disc_base_dir, use_drive_letters)

    # Return token map
    return token_map

# Path with every token in token_map replaced by its value
def resolve_path(
    path,
    token_map = None):
    token_map = {} if token_map is None else token_map
    for token, replacement in token_map.items():
        if token in path:
            path = path.replace(token, replacement)
    return path

# Drive letter, base and remaining parts of a path inside a Wine prefix's drive_c or dosdevices folder
def split_wine_prefix_parts(prefix_dir, path_parts):
    if path_parts[0] == "drive_c":
        return "c", paths.join_paths(prefix_dir, "drive_c"), path_parts[1:]
    if path_parts[0] == "dosdevices" and len(path_parts) > 1 and path_parts[1]:
        return path_parts[1][0].lower(), paths.join_paths(prefix_dir, "dosdevices", path_parts[1]), path_parts[2:]
    return "", "", path_parts[1:]

# Drive letter, extra, base and remaining parts of a path inside a Sandboxie box's drive or current user folder
def split_sandboxie_prefix_parts(options, path_parts):
    if path_parts[0] == "drive" and len(path_parts) > 1 and path_parts[1]:
        return path_parts[1].lower(), "", get_sandboxie_real_drive_path(options, path_parts[1]), path_parts[2:]
    if path_parts[:2] == ["user", "current"]:
        path_drive_extra = paths.normalize_file_path(paths.join_paths("Users", getpass.getuser()), separator = config.OS_PATHSEP)
        return "c", path_drive_extra, get_sandboxie_user_profile_path(options), path_parts[2:]
    return "", "", "", path_parts[1:]

# Drive letter, offset, extra and base of a host path inside the prefix folder; empty letter when it is on no drive
def split_prefix_inner_path(new_path, options):
    prefix_dir = options.get_prefix_dir()
    path_parts = new_path[len(prefix_dir + config.OS_PATHSEP):].split(config.OS_PATHSEP)
    if options.is_wine_prefix():
        path_drive_letter, path_drive_base, path_rest = split_wine_prefix_parts(prefix_dir, path_parts)
        path_drive_extra = ""
    else:
        path_drive_letter, path_drive_extra, path_drive_base, path_rest = split_sandboxie_prefix_parts(options, path_parts)
    return path_drive_letter, config.OS_PATHSEP.join(path_rest), path_drive_extra, path_drive_base

# Drive letter, offset, extra and base of a Wine drive path; a host path lands on z
def split_wine_drive_path(new_path, options, is_virtual_path):
    if is_virtual_path:
        path_drive_letter = paths.get_directory_drive(new_path)
    else:
        path_drive_letter = "z"
    path_drive_offset = new_path[len(paths.get_directory_anchor(new_path)):]
    return path_drive_letter, path_drive_offset, "", get_wine_real_drive_path(options, path_drive_letter)

# Drive letter, offset, extra and base of a Sandboxie drive path, under the user profile when it is in the user's folder
def split_sandboxie_drive_path(new_path, options):
    path_drive_letter = paths.get_directory_drive(new_path)
    path_drive_offset = new_path[len(paths.get_directory_anchor(new_path)):]
    path_drive_extra = paths.normalize_file_path(paths.join_paths("Users", getpass.getuser()), separator = config.OS_PATHSEP)
    if path_drive_offset == path_drive_extra or path_drive_offset.startswith(path_drive_extra + config.OS_PATHSEP):
        path_drive_base = get_sandboxie_user_profile_path(options)
        path_drive_offset = path_drive_offset[len(path_drive_extra + config.OS_PATHSEP):]
        return path_drive_letter, path_drive_offset, path_drive_extra, path_drive_base
    return path_drive_letter, path_drive_offset, "", get_sandboxie_real_drive_path(options, path_drive_letter)

# Drive letter, offset, extra and base of a path with no prefix; under Wine the host drive is z
def split_host_drive_path(new_path):
    path_drive_offset = new_path[len(paths.get_directory_anchor(new_path)):]
    path_drive_base = paths.get_directory_drive(new_path)
    if platform_info.is_wine_platform():
        path_drive_letter = "z"
    else:
        path_drive_letter = paths.get_directory_drive(new_path)
    return path_drive_letter, path_drive_offset, "", path_drive_base

# Drive parts of a normalized path with the virtual and real flags it settles on: host paths under a Wine root or with no prefix are real
def split_prefix_drive_path(new_path, options, is_virtual_path, is_real_path):

    # Fix path inconsistencies
    if options.is_wine_prefix():
        if is_virtual_path and new_path.startswith(config.DRIVE_ROOT_POSIX):
            is_virtual_path = False
            is_real_path = True

    # Real path inside the prefix
    prefix_dir = options.get_prefix_dir()
    is_inside_prefix = (new_path == prefix_dir or new_path.startswith(prefix_dir + config.OS_PATHSEP))
    if is_real_path and is_inside_prefix and options.is_prefix():
        return split_prefix_inner_path(new_path, options), is_virtual_path, is_real_path

    # Wine
    if options.is_wine_prefix():
        return split_wine_drive_path(new_path, options, is_virtual_path), is_virtual_path, is_real_path

    # Sandboxie
    if options.is_sandboxie_prefix():
        return split_sandboxie_drive_path(new_path, options), is_virtual_path, is_real_path

    # Neither
    return split_host_drive_path(new_path), False, True

# Full virtual and real forms of a path from its drive parts, asserting the original matches its own form
def build_full_prefix_paths(new_path, is_virtual_path, drive_parts):
    path_drive_letter, path_drive_offset, path_drive_extra, path_drive_base = drive_parts
    path_full_virtual = ""
    path_full_real = ""
    if is_virtual_path:
        path_full_virtual = new_path
        path_full_real = paths.join_paths(path_drive_base, path_drive_offset)
    else:
        path_full_virtual += path_drive_letter.upper() + ":" + config.OS_PATHSEP
        path_full_virtual += path_drive_extra + config.OS_PATHSEP
        path_full_virtual += path_drive_offset
        path_full_real = new_path

    # Check for consistency
    if is_virtual_path:
        validation.assert_condition(
            condition = (new_path == path_full_virtual),
            description = "Original virtual path must match constructed virtual path")
    else:
        validation.assert_condition(
            condition = (new_path == path_full_real),
            description = "Original real path must match constructed real path")
    return path_full_virtual, path_full_real

# Whether the path is valid, exactly one of virtual or real, and the options have a valid prefix folder
def can_get_prefix_path_info(path, options, is_virtual_path, is_real_path):
    if not paths.is_path_valid(path):
        return False
    if is_virtual_path == is_real_path:
        return False
    return bool(options.has_valid_prefix_dir())

# Path info dict for a normalized path from its drive parts, with both full forms checked against the original
def build_prefix_path_info(new_path, options, is_virtual_path, is_real_path, drive_parts):
    path_full_virtual, path_full_real = build_full_prefix_paths(new_path, is_virtual_path, drive_parts)
    path_drive_letter, path_drive_offset, path_drive_extra, path_drive_base = drive_parts
    info = {}
    info["path"] = paths.normalize_file_path(new_path)
    info["prefix"] = paths.normalize_file_path(options.get_prefix_dir())
    info["is_virtual"] = is_virtual_path
    info["is_real"] = is_real_path
    info["is_wine"] = options.is_wine_prefix()
    info["is_sandboxie"] = options.is_sandboxie_prefix()
    info["letter"] = path_drive_letter
    info["base"] = paths.normalize_file_path(path_drive_base)
    info["offset"] = paths.normalize_file_path(path_drive_offset)
    if path_drive_extra:
        info["extra"] = paths.normalize_file_path(path_drive_extra)
    else:
        info["extra"] = path_drive_extra
    info["real"] = paths.normalize_file_path(path_full_real)
    info["virtual"] = paths.normalize_file_path(path_full_virtual, force_windows = True)
    return info

# Split a virtual (drive letter) or real (host) path into prefix, letter, base and offset with both forms; None when invalid
def get_prefix_path_info(
    path,
    options,
    is_virtual_path = False,
    is_real_path = False):

    # Check path, path kind and prefix
    if not can_get_prefix_path_info(path, options, is_virtual_path, is_real_path):
        return None

    # These are some potential types of paths
    # - /home/user/.wine/drive_c/foo/bar
    # - /home/user/.wine/dosdevices/c:/foo/bar
    # - C:/Sandboxie/Sandbox/Default/drive/C/foo/bar
    # - C:/Sandboxie/Sandbox/Default/user/current/foo/bar
    # - C:/foo/bar

    # Copy params
    new_path = copy.deepcopy(path)
    new_options = options.copy()

    # Normalize paths
    new_path = paths.normalize_file_path(new_path, separator = config.OS_PATHSEP)
    new_options.set_prefix_dir(paths.normalize_file_path(new_options.get_prefix_dir(), separator = config.OS_PATHSEP))

    # Split into drive letter, offset, extra and base
    drive_parts, is_virtual_path, is_real_path = split_prefix_drive_path(new_path, new_options, is_virtual_path, is_real_path)

    # Path has to land on a drive
    if not drive_parts[0]:
        return None

    # Return path info
    return build_prefix_path_info(new_path, new_options, is_virtual_path, is_real_path, drive_parts)
