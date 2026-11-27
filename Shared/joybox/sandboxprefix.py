# Creating Wine and Sandboxie prefixes, either self-contained or with the user
# folders linked to a shared general prefix, and stopping Wine once a command is
# done with it. Their tools run through commandrun, as they are; preparing them
# for a prefix would need the very prefix being made.

# Imports
import os
import os.path

# Local imports
from joybox import config
from joybox import fileops
from joybox import commandbase
from joybox import commandrun
from joybox import process
from joybox import programs
from joybox import paths
from joybox import sandbox
from joybox import prefixlayout

###########################################################

# Create wine prefix
def create_wine_prefix(
    options,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Make directory
    success = fileops.make_directory(
        src = options.get_prefix_dir(),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return False

    # Get wine boot tool
    wine_boot_tool = programs.get_tool_program("WineBoot")

    # Get wine tricks tool
    wine_tricks_tool = programs.get_tool_program("WineTricks")

    # Copy params
    new_options = options.copy()
    new_options.set_is_wine_prefix(True)

    # Initialize prefix
    cmds_to_run = []
    cmds_to_run.append([wine_boot_tool])
    if len(new_options.get_tricks()) > 0:
        cmds_to_run.append([wine_tricks_tool] + new_options.get_tricks())
    for cmd in cmds_to_run:
        new_options.set_blocking_processes([commandbase.get_starter_command(cmd)])
        new_cmd, new_options = sandbox.setup_prefix_environment(
            cmd = cmd,
            options = new_options,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        code = commandrun.run_prepared_returncode_command(
            cmd = new_cmd,
            options = new_options,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if code != 0:
            return False

    # Creation successful
    return True

# Create sandboxie prefix
def create_sandboxie_prefix(
    options,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Make directories
    for prefix_subdir in [
        options.get_prefix_dir(),
        prefixlayout.get_sandboxie_real_drive_path(options, "C"),
        prefixlayout.get_sandboxie_user_profile_path(options)]:
        success = fileops.make_directory(
            src = prefix_subdir,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return False

    # Get sandboxie ini tool
    sandboxie_ini_tool = programs.get_tool_program("SandboxieIni")

    # Copy params
    new_options = options.copy()
    new_options.set_is_sandboxie_prefix(True)
    new_options.set_blocking_processes([sandboxie_ini_tool])
    new_options.set_is_shell(True)

    # Initialize prefix
    box_params = [
        ("Enabled", "y"),
        ("FileRootPath", new_options.get_prefix_dir()),
        ("BlockNetParam", "n"),
        ("BlockNetworkFiles", "y"),
        ("RecoverFolder", "%Desktop%"),
        ("BorderColor", "#00ffff,off,6"),
        ("ConfigLevel", "10"),
        ("BoxNameTitle", "-"),
        ("CopyLimitKb", "-1"),
        ("NoSecurityIsolation", "y"),
        ("Template", "OpenBluetooth")
    ]
    for param, value in box_params:
        cmd = [sandboxie_ini_tool, "set", new_options.get_prefix_name().val(), param, value]
        new_cmd, param_options = sandbox.setup_prefix_environment(
            cmd = cmd,
            options = new_options,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        code = commandrun.run_prepared_returncode_command(
            cmd = new_cmd,
            options = param_options,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if code != 0:
            return False

    # Creation successful
    return True

# Clean existing prefix
def clean_existing_prefix(
    options,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    if not os.path.lexists(options.get_prefix_dir()):
        return True
    return fileops.remove_object(
        obj = options.get_prefix_dir(),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# Create basic prefix
def create_basic_prefix(
    options,
    clean_existing = True,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Check prefix
    if not options.has_valid_prefix_dir():
        return False

    # Clean prefix
    if clean_existing:
        success = clean_existing_prefix(
            options = options,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return False

    # Setup wine prefix
    if options.is_wine_prefix():

        # Create wine prefix
        success = create_wine_prefix(
            options = options,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return False

        # Replace symlinked directories
        return fileops.replace_symlinked_directories(
            src = prefixlayout.get_wine_user_profile_path(options),
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    # Setup sandboxie prefix
    elif options.is_sandboxie_prefix():

        # Create sandboxie prefix
        return create_sandboxie_prefix(
            options = options,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    # Not a prefix
    return False

# Create linked prefix
def create_linked_prefix(
    options,
    other_links = (),
    clean_existing = True,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Check prefix
    if not options.has_valid_prefix_dir():
        return False
    if not options.is_prefix():
        return False

    # Check general prefix
    if not options.has_valid_general_prefix_dir():
        return False

    # Clean prefix
    if clean_existing:
        success = clean_existing_prefix(
            options = options,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = False)
        if not success:
            return False

    # Create general prefix subfolders
    for folder in config.computer_user_folders:
        success = fileops.make_directory(
            src = paths.join_paths(options.get_general_prefix_dir(), folder),
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return False

    # Get prefix c drive
    prefix_c_drive = prefixlayout.get_real_c_drive_path(options)

    # Setup wine prefix
    if options.is_wine_prefix():

        # Create wine prefix
        success = create_wine_prefix(
            options = options,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return False

        # Link prefix
        success = fileops.create_symlink(
            src = options.get_general_prefix_dir(),
            dest = prefixlayout.get_wine_user_profile_path(options),
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return False

    # Setup sandboxie prefix
    else:

        # Create sandboxie prefix
        success = create_sandboxie_prefix(
            options = options,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return False

    # Link other paths
    for other_link in other_links:
        path_from = other_link["from"]
        path_to = paths.join_paths(prefix_c_drive, other_link["to"])
        if not paths.does_path_exist(path_from):
            continue
        success = fileops.create_symlink(
            src = path_from,
            dest = path_to,
            cwd = prefix_c_drive,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return False

    # Creation successful
    return True

# Set up a prefix on the options and create it, then record its user profile and C drive
def create_prefix(
    options,
    is_wine_prefix,
    is_sandboxie_prefix,
    prefix_name,
    prefix_dir = None,
    general_prefix_dir = None,
    linked_prefix = False,
    other_links = None,
    clean_existing = True,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get other links
    other_links = [] if other_links is None else other_links

    # Setup prefix
    options.setup_prefix(
        is_wine_prefix = is_wine_prefix,
        is_sandboxie_prefix = is_sandboxie_prefix,
        prefix_name = prefix_name,
        prefix_dir = prefix_dir,
        general_prefix_dir = general_prefix_dir)

    # Create prefix
    if linked_prefix:
        success = create_linked_prefix(
            options = options,
            other_links = other_links,
            clean_existing = clean_existing,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return False
    else:
        success = create_basic_prefix(
            options = options,
            clean_existing = clean_existing,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return False

    # Set prefix user profile dir
    options.set_prefix_user_profile_dir(prefixlayout.get_user_profile_path(options))
    if not options.has_existing_prefix_user_profile_dir():
        return False

    # Set prefix C drive
    options.set_prefix_c_drive_virtual(config.DRIVE_ROOT_WINDOWS)
    options.set_prefix_c_drive_real(prefixlayout.get_real_c_drive_path(options))
    if not options.has_existing_prefix_c_drive_real():
        return False

    # Should be successful
    return True

# Cleanup wine
def cleanup_wine(verbose = False, pretend_run = False, exit_on_failure = False):

    # Get wine server tool
    wine_server_tool = programs.get_tool_program("WineServer")

    # Kill processes running under wine
    commandrun.run_prepared_returncode_command(
        cmd = [wine_server_tool, "-k"],
        options = commandbase.create_command_options(
            is_shell = True),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Kill wine itself
    process.kill_active_named_processes([wine_server_tool])
