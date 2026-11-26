# Imports
import getpass
import copy

# Local imports
from joybox import config
from joybox import validation
from joybox import fileops
from joybox import commandbase
from joybox import programs
from joybox import paths
from joybox import process
from joybox import cmdline
from joybox import platform_info

###########################################################

# Check if command should be run via wine
def should_be_run_via_wine(cmd):

    # Check platform
    if not platform_info.is_wine_platform():
        return False

    # Already using wine
    if commandbase.get_starter_command(cmd) == get_wine_command():
        return False

    # Wine runs windows executable formats only
    if not commandbase.is_windows_executable_command(cmd):
        return False

    # Cached game commands or sandboxed local programs should use wine
    is_cached_game_cmd = commandbase.is_cached_game_command(cmd)
    is_sandboxed_program_cmd = commandbase.is_local_sandboxed_program_command(cmd)
    return (
        is_cached_game_cmd or
        is_sandboxed_program_cmd
    )

# Check if command should be run via sandboxie
def should_be_run_via_sandboxie(cmd):

    # Check platform
    if not platform_info.is_sandboxie_platform():
        return False

    # Already using sandboxie
    if commandbase.get_starter_command(cmd) == get_sandboxie_command():
        return False

    # Sandboxie runs windows executable formats only
    if not commandbase.is_windows_executable_command(cmd):
        return False

    # Cached game commands or sandboxed local programs should use sandboxie
    is_cached_game_cmd = commandbase.is_cached_game_command(cmd)
    is_sandboxed_program_cmd = commandbase.is_local_sandboxed_program_command(cmd)
    return (
        is_cached_game_cmd or
        is_sandboxed_program_cmd
    )

###########################################################

# Get wine command
def get_wine_command():
    return programs.get_tool_program("Wine")

# Get sandboxie command
def get_sandboxie_command():
    return programs.get_tool_program("Sandboxie")

###########################################################

# Get wine blocking processes
def get_wine_blocking_processes():
    return [
        programs.get_tool_program("WineServer")
    ]

# Get sandboxie blocking processes
def get_sandboxie_blocking_processes():
    return [
        programs.get_tool_program("Sandboxie"),
        programs.get_tool_program("SandboxieIni"),
        programs.get_tool_program("SandboxieRpcss"),
        programs.get_tool_program("SandboxieDcomlaunch")
    ]

# Get blocking processes
def get_blocking_processes(options, initial_processes = None):
    initial_processes = [] if initial_processes is None else initial_processes
    blocking_processes = copy.deepcopy(initial_processes)
    if options.is_wine_prefix():
        blocking_processes += get_wine_blocking_processes()
    elif options.is_sandboxie_prefix():
        blocking_processes += get_sandboxie_blocking_processes()
    return blocking_processes

###########################################################

# Get wine prefix
def get_wine_prefix(options):
    return paths.join_paths(programs.get_tool_path_config_value("Wine", "sandbox_dir"), options.get_prefix_name())

# Get sandboxie prefix
def get_sandboxie_prefix(options):
    return paths.join_paths(programs.get_tool_path_config_value("Sandboxie", "sandbox_dir"), options.get_prefix_name())

# Get prefix
def get_prefix(options):
    prefix_dir = None
    if options.get_prefix_name():
        if options.is_wine_prefix():
            prefix_dir = get_wine_prefix(options)
        elif options.is_sandboxie_prefix():
            prefix_dir = get_sandboxie_prefix(options)
    return prefix_dir

###########################################################

# Get wine real drive path
def get_wine_real_drive_path(options, drive):
    if drive.lower() == "c":
        return paths.join_paths(options.get_prefix_dir(), "drive_c")
    else:
        return paths.join_paths(options.get_prefix_dir(), "dosdevices", drive.lower() + ":")

# Get sandboxie real drive path
def get_sandboxie_real_drive_path(options, drive):
    return paths.join_paths(options.get_prefix_dir(), "drive", drive.upper())

# Get real drive path
def get_real_drive_path(options, drive):
    real_drive_path = None
    if options.is_wine_prefix():
        real_drive_path = get_wine_real_drive_path(options, drive)
    elif options.is_sandboxie_prefix():
        real_drive_path = get_sandboxie_real_drive_path(options, drive)
    return real_drive_path

# Get real c drive path
def get_real_c_drive_path(options):
    return get_real_drive_path(options, "c")

###########################################################

# Get wine user profile path
def get_wine_user_profile_path(options):
    return paths.normalize_file_path(paths.join_paths(options.get_prefix_dir(), "drive_c", "users", getpass.getuser()))

# Get sandboxie user profile path
def get_sandboxie_user_profile_path(options):
    return paths.normalize_file_path(paths.join_paths(options.get_prefix_dir(), "user", "current"))

# Get user profile path
def get_user_profile_path(options):
    user_profile_dir = None
    if options.is_wine_prefix():
        user_profile_dir = get_wine_user_profile_path(options)
    elif options.is_sandboxie_prefix():
        user_profile_dir = get_sandboxie_user_profile_path(options)
    return user_profile_dir

###########################################################

# Get wine public profile path
def get_wine_public_profile_path(options):
    return paths.normalize_file_path(paths.join_paths(options.get_prefix_dir(), "drive_c", "users", "Public"))

# Get sandboxie public profile path
def get_sandboxie_public_profile_path(options):
    return paths.normalize_file_path(paths.join_paths(options.get_prefix_dir(), "drive", "C", "Public"))

# Get public profile path
def get_public_profile_path(options):
    public_profile_dir = None
    if options.is_wine_prefix():
        public_profile_dir = get_wine_public_profile_path(options)
    elif options.is_sandboxie_prefix():
        public_profile_dir = get_sandboxie_public_profile_path(options)
    return public_profile_dir

###########################################################

# Install wine dlls
def install_wine_dlls(
    options,
    dlls_32 = (),
    dlls_64 = (),
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    wine_c_drive = get_wine_real_drive_path(options, "c")
    wine_system32_dir = paths.join_paths(wine_c_drive, "windows", "system32")
    wine_syswow64_dir = paths.join_paths(wine_c_drive, "windows", "syswow64")
    if options.is_32_bit():
        for lib32 in dlls_32:
            fileops.copy_file_or_directory(
                src = lib32,
                dest = wine_system32_dir,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
    else:
        for lib64 in dlls_64:
            fileops.copy_file_or_directory(
                src = lib64,
                dest = paths.join_paths(wine_c_drive, "windows", "system32"),
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
        for lib32 in dlls_32:
            fileops.copy_file_or_directory(
                src = lib32,
                dest = wine_syswow64_dir,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)

# Install sandboxie dlls
def install_sandboxie_dlls(
    options,
    dlls_32 = (),
    dlls_64 = (),
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    pass

# Install dlls
def install_dlls(
    options,
    dlls_32 = None,
    dlls_64 = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    dlls_32 = [] if dlls_32 is None else dlls_32
    dlls_64 = [] if dlls_64 is None else dlls_64
    if options.is_wine_prefix():
        install_wine_dlls(
            options = options,
            dlls_32 = dlls_32,
            dlls_64 = dlls_64,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
    elif options.is_sandboxie_prefix():
        install_sandboxie_dlls(
            options = options,
            dlls_32 = dlls_32,
            dlls_64 = dlls_64,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

###########################################################

# Restore registry
def restore_registry(
    options,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Imports
    from joybox import registry

    # Get registry dir
    registry_dir = options.get_prefix_user_profile_registry_dir()
    if not registry_dir:
        return False

    # Get registry file
    registry_file = ""
    if options.get_prefix_name() == config.PrefixType.SETUP:
        registry_file = paths.join_paths(registry_dir, config.registry_filename_setup)
    elif options.get_prefix_name() == config.PrefixType.GAME:
        registry_file = paths.join_paths(registry_dir, config.registry_filename_game)
    if not paths.does_path_exist(registry_file):
        return True

    # Import registry file
    return registry.import_registry_file(
        registry_file = registry_file,
        options = options,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# Backup registry
def backup_registry(
    options,
    registry_keys = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get registry keys
    registry_keys = [] if registry_keys is None else registry_keys

    # Imports
    from joybox import registry

    # Ignore empty keys
    if not registry_keys:
        return True

    # Get registry dir
    registry_dir = options.get_prefix_user_profile_registry_dir()
    if not registry_dir:
        return False

    # Get registry file, export keys, and ignore keys
    if options.get_prefix_name() == config.PrefixType.SETUP:
        registry_file = paths.join_paths(registry_dir, config.registry_filename_setup)
        registry_export_keys = config.registry_export_keys_setup
        registry_ignore_keys = config.ignored_registry_keys_setup
    elif options.get_prefix_name() == config.PrefixType.GAME:
        registry_file = paths.join_paths(registry_dir, config.registry_filename_game)
        registry_export_keys = config.registry_export_keys_game
        registry_ignore_keys = config.ignored_registry_keys_game
    else:
        return False

    # Backup registry
    return registry.backup_user_registry(
        registry_file = registry_file,
        options = options,
        export_keys = registry_export_keys,
        ignore_keys = registry_ignore_keys,
        keep_keys = registry_keys,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

###########################################################

# Build token map
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
        token_map[config.token_store_install_dir] = store_install_dir
    if game_install_dir:
        token_map[config.token_game_install_dir] = game_install_dir
    if setup_base_dir:
        token_map[config.token_setup_main_root] = setup_base_dir
    if hdd_base_dir:
        token_map[config.token_hdd_main_root] = hdd_base_dir
        token_map[config.token_dos_main_root] = paths.join_paths(hdd_base_dir, config.computer_folder_dos)
        token_map[config.token_scumm_main_root] = paths.join_paths(hdd_base_dir, config.computer_folder_scumm)

    # Add discs
    disc_letter_index = 0
    for disc_file in disc_files:

        # Get drive letter
        disc_letter_drive = config.drives_regular[disc_letter_index]
        disc_letter_index += 1

        # Get file basename
        disc_file_basename = paths.get_filename_basename(disc_file)

        # Find which token to use
        disc_token_to_use = config.token_disc_main_root
        for disc_token, disc_name in config.token_disc_names.items():
            if disc_name in disc_file:
                disc_token_to_use = disc_token
                break

        # Add entry
        if use_drive_letters:
            token_map[disc_token_to_use] = "%s:/" % disc_letter_drive
        elif disc_base_dir:
            token_map[disc_token_to_use] = paths.join_paths(disc_base_dir, disc_file_basename)
        else:
            token_map[disc_token_to_use] = disc_file_basename

    # Return token map
    return token_map

# Resolve path
def resolve_path(
    path,
    token_map = None):
    token_map = {} if token_map is None else token_map
    for token, replacement in token_map.items():
        if token in path:
            path = path.replace(token, replacement)
    return path

###########################################################

# Get prefix path info
def get_prefix_path_info(
    path,
    options,
    is_virtual_path = False,
    is_real_path = False):

    # Check path
    if not paths.is_path_valid(path):
        return None

    # Check path kind
    if is_virtual_path == is_real_path:
        return None

    # Check prefix
    if not options.has_valid_prefix_dir():
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
    new_path = paths.normalize_file_path(new_path, separator = config.os_pathsep)
    new_options.set_prefix_dir(paths.normalize_file_path(new_options.get_prefix_dir(), separator = config.os_pathsep))

    # Fix path inconsistencies
    if new_options.is_wine_prefix():
        if is_virtual_path and new_path.startswith(config.drive_root_posix):
            is_virtual_path = False
            is_real_path = True

    # Initialize letter, offset, and base
    path_drive_letter = ""
    path_drive_offset = ""
    path_drive_extra = ""
    path_drive_base = ""

    # Real path inside the prefix
    prefix_dir = new_options.get_prefix_dir()
    is_inside_prefix = (new_path == prefix_dir or new_path.startswith(prefix_dir + config.os_pathsep))
    if is_real_path and is_inside_prefix and new_options.is_prefix():
        path_parts = new_path[len(prefix_dir + config.os_pathsep):].split(config.os_pathsep)
        path_rest = path_parts[1:]
        if new_options.is_wine_prefix():
            if path_parts[0] == "drive_c":
                path_drive_letter = "c"
                path_drive_base = paths.join_paths(prefix_dir, "drive_c")
            elif path_parts[0] == "dosdevices" and len(path_parts) > 1 and path_parts[1]:
                path_drive_letter = path_parts[1][0].lower()
                path_drive_base = paths.join_paths(prefix_dir, "dosdevices", path_parts[1])
                path_rest = path_parts[2:]
        else:
            if path_parts[0] == "drive" and len(path_parts) > 1 and path_parts[1]:
                path_drive_letter = path_parts[1].lower()
                path_drive_base = get_sandboxie_real_drive_path(new_options, path_parts[1])
                path_rest = path_parts[2:]
            elif path_parts[:2] == ["user", "current"]:
                path_drive_letter = "c"
                path_drive_extra = paths.normalize_file_path(paths.join_paths("Users", getpass.getuser()), separator = config.os_pathsep)
                path_drive_base = get_sandboxie_user_profile_path(new_options)
                path_rest = path_parts[2:]
        path_drive_offset = config.os_pathsep.join(path_rest)

    # Wine
    elif new_options.is_wine_prefix():
        if is_virtual_path:
            path_drive_letter = paths.get_directory_drive(new_path)
        else:
            path_drive_letter = "z"
        path_drive_offset = new_path[len(paths.get_directory_anchor(new_path)):]
        path_drive_base = get_wine_real_drive_path(new_options, path_drive_letter)

    # Sandboxie
    elif new_options.is_sandboxie_prefix():
        path_drive_letter = paths.get_directory_drive(new_path)
        path_drive_offset = new_path[len(paths.get_directory_anchor(new_path)):]
        path_drive_extra = paths.normalize_file_path(paths.join_paths("Users", getpass.getuser()), separator = config.os_pathsep)
        if path_drive_offset == path_drive_extra or path_drive_offset.startswith(path_drive_extra + config.os_pathsep):
            path_drive_base = get_sandboxie_user_profile_path(new_options)
            path_drive_offset = path_drive_offset[len(path_drive_extra + config.os_pathsep):]
        else:
            path_drive_extra = ""
            path_drive_base = get_sandboxie_real_drive_path(new_options, path_drive_letter)

    # Neither
    else:
        path_drive_offset = new_path[len(paths.get_directory_anchor(new_path)):]
        path_drive_base = paths.get_directory_drive(new_path)
        if platform_info.is_wine_platform():
            path_drive_letter = "z"
        else:
            path_drive_letter = paths.get_directory_drive(new_path)
        is_virtual_path = False
        is_real_path = True

    # Path has to land on a drive
    if not path_drive_letter:
        return None

    # Construct full virtual and real paths
    path_full_virtual = ""
    path_full_real = ""
    if is_virtual_path:
        path_full_virtual = new_path
        path_full_real = paths.join_paths(path_drive_base, path_drive_offset)
    else:
        path_full_virtual += path_drive_letter.upper() + ":" + config.os_pathsep
        path_full_virtual += path_drive_extra + config.os_pathsep
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

    # Return path info
    info = {}
    info["path"] = paths.normalize_file_path(new_path)
    info["prefix"] = paths.normalize_file_path(new_options.get_prefix_dir())
    info["is_virtual"] = is_virtual_path
    info["is_real"] = is_real_path
    info["is_wine"] = new_options.is_wine_prefix()
    info["is_sandboxie"] = new_options.is_sandboxie_prefix()
    info["letter"] = path_drive_letter
    info["base"] = paths.normalize_file_path(path_drive_base)
    info["offset"] = paths.normalize_file_path(path_drive_offset)
    if len(path_drive_extra):
        info["extra"] = paths.normalize_file_path(path_drive_extra)
    else:
        info["extra"] = path_drive_extra
    info["real"] = paths.normalize_file_path(path_full_real)
    info["virtual"] = paths.normalize_file_path(path_full_virtual, force_windows = True)
    return info

###########################################################

# Setup prefix environment
def setup_prefix_environment(
    cmd,
    options = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Check options
    if not options:
        options = commandbase.create_command_options()

    # Ignore non-prefix environments
    if not options.is_prefix():
        return (cmd, options)

    # Copy params
    new_cmd = copy.deepcopy(cmd)
    new_options = options.copy()

    # Modify for wine
    if new_options.is_wine_prefix():

        # Add blocking processes
        new_options.add_blocking_processes(get_wine_blocking_processes())

        # Improve performance by not showing everything
        # To show only errors, change to fixme-all
        new_options.set_env_var("WINEDEBUG", "-all")

        # Set prefix location
        if new_options.has_valid_prefix_dir():
            new_options.set_env_var("WINEPREFIX", new_options.get_prefix_dir())

        # Set prefix bitness
        if new_options.is_32_bit():
            new_options.set_env_var("WINEARCH", "win32")
        else:
            new_options.set_env_var("WINEARCH", "win64")

        # Set prefix overrides
        wine_overrides = ["winemenubuilder.exe=d"]
        wine_overrides += new_options.get_overrides()
        new_options.set_env_var("WINEDLLOVERRIDES", ";".join(wine_overrides))

        # Map the current working directory to the prefix
        if new_options.is_prefix_mapped_cwd() and new_options.has_valid_cwd() and new_options.has_valid_prefix_dir():
            fileops.create_symlink(
                src = new_options.get_cwd(),
                dest = get_real_drive_path(
                    options = new_options,
                    drive = config.drive_prefix_cwd),
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)

    # Modify for sandboxie
    else:

        # Add blocking processes
        new_options.add_blocking_processes(get_sandboxie_blocking_processes())

    # Return results
    return (new_cmd, new_options)

# Setup prefix command
def setup_prefix_command(
    cmd,
    options = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Imports
    from joybox import gui

    # Check options
    if not options:
        options = commandbase.create_command_options()

    # Ignore non-prefix commands
    if not options.is_prefix():
        return (cmd, options)

    # Get original command info
    orig_cmd_starter = commandbase.get_starter_command(cmd)
    orig_cmd_list = cmdline.create_command_list(cmd)
    if len(orig_cmd_list) == 0:
        return (cmd, options)

    # Copy params
    new_cmd = []
    new_options = options.copy()

    # Create command
    if new_options.is_wine_prefix():
        new_cmd = [get_wine_command()]
        if new_options.use_virtual_desktop():
            new_cmd += ["explorer", "/desktop=" + new_options.get_desktop_dimensions()]
    else:
        new_cmd = [
            get_sandboxie_command(),
            "/box:%s" % options.get_prefix_name().val()
        ]
        if new_options.get_prefix_name() == config.PrefixType.TOOL:
            new_cmd += ["/hide_window"]

    # Adjust command based on executable type
    if orig_cmd_starter.endswith(".lnk"):
        info = fileops.get_link_info(
            lnk_path = orig_cmd_starter,
            lnk_base_path = options.get_lnk_base_path())
        has_valid_target = paths.does_path_exist(info["target"])
        has_valid_cwd = paths.does_path_exist(info["cwd"])
        if not has_valid_target or not has_valid_cwd:
            gui.display_error_popup(
                title_text = "Unable to resolve LNK file",
                message_text = "Unable to resolve LNK file %s to an actual target" % orig_cmd_starter)
        new_cmd += [info["target"]]
        new_cmd += info["args"]
        new_options.set_cwd(info["cwd"])
    elif orig_cmd_starter.endswith(".bat"):
        if options.is_sandboxie_prefix():
            new_cmd += ["cmd", "/c"]
        new_cmd += orig_cmd_list
    else:
        new_cmd += orig_cmd_list

    # Sync cwd to prefix cwd
    new_options.sync_cwd_to_prefix_cwd()

    # Return results
    return (new_cmd, new_options)

###########################################################

# Cleanup wine
def cleanup_wine(cmd, options, verbose = False, pretend_run = False, exit_on_failure = False):

    # Imports
    from joybox import command

    # Get wine server tool
    wine_server_tool = programs.get_tool_program("WineServer")

    # Kill processes running under wine
    command.run_returncode_command(
        cmd = [wine_server_tool, "-k"],
        options = commandbase.create_command_options(
            is_shell = True),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Kill wine itself
    process.kill_active_named_processes([wine_server_tool])

# Cleanup sandboxie
def cleanup_sandboxie(cmd, options, verbose = False, pretend_run = False, exit_on_failure = False):
    pass

###########################################################
