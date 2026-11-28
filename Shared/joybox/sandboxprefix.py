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

# Make the prefix directory, run wineboot, then winetricks with the options' tricks; False on any non-zero exit
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
    return _run_wine_prefix_commands(
        cmds_to_run = cmds_to_run,
        new_options = new_options,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# Run each command inside the prefix, each blocking on its own starter; False at the first non-zero exit
def _run_wine_prefix_commands(cmds_to_run, new_options, verbose, pretend_run, exit_on_failure):
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

# Make the box directories and write the box settings with SandboxieIni; False on any non-zero exit
def create_sandboxie_prefix(
    options,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Make directories
    success = fileops.make_directories(
        dirs = [
            options.get_prefix_dir(),
            prefixlayout.get_sandboxie_real_drive_path(options, "C"),
            prefixlayout.get_sandboxie_user_profile_path(options)],
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
    return _write_sandboxie_box_params(
        sandboxie_ini_tool = sandboxie_ini_tool,
        new_options = new_options,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# Set each box setting for the prefix's box with SandboxieIni; False at the first non-zero exit
def _write_sandboxie_box_params(sandboxie_ini_tool, new_options, verbose, pretend_run, exit_on_failure):
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

# Remove the prefix directory, even a dangling link; True when nothing is there
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

# Remove the prefix directory when clean_existing is set; True when skipped
def _clean_prefix_if_requested(options, clean_existing, verbose, pretend_run, exit_on_failure):
    if not clean_existing:
        return True
    return clean_existing_prefix(
        options = options,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# Create a standalone Wine or Sandboxie prefix, replacing Wine's symlinked profile folders with real ones
# False when the options name no prefix type
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
    success = _clean_prefix_if_requested(options, clean_existing, verbose, pretend_run, exit_on_failure)
    if not success:
        return False

    # Setup wine prefix
    if options.is_wine_prefix():
        return _create_basic_wine_prefix(
            options = options,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    # Setup sandboxie prefix
    if options.is_sandboxie_prefix():

        # Create sandboxie prefix
        return create_sandboxie_prefix(
            options = options,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    # Not a prefix
    return False

# Create a Wine prefix and swap its symlinked user profile folders for real directories
def _create_basic_wine_prefix(options, verbose, pretend_run, exit_on_failure):

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

# Create a prefix whose user profile links to the shared general prefix, then link other_links into its C drive
# Links whose source is missing are skipped
def create_linked_prefix(
    options,
    other_links = (),
    clean_existing = True,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Check prefixes
    if not _has_linkable_prefix(options):
        return False

    # Clean prefix
    success = _clean_prefix_if_requested(options, clean_existing, verbose, pretend_run, False)
    if not success:
        return False

    # Create general prefix subfolders
    success = _make_general_prefix_folders(options, verbose, pretend_run, exit_on_failure)
    if not success:
        return False

    # Get prefix c drive
    prefix_c_drive = prefixlayout.get_real_c_drive_path(options)

    # Setup wine or sandboxie prefix
    success = _create_linked_prefix_of_type(options, verbose, pretend_run, exit_on_failure)
    if not success:
        return False

    # Link other paths
    return _link_other_paths(
        other_links = other_links,
        prefix_c_drive = prefix_c_drive,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# Whether the options name a valid prefix of a known type and a valid general prefix to link to
def _has_linkable_prefix(options):

    # Check prefix
    if not options.has_valid_prefix_dir():
        return False
    if not options.is_prefix():
        return False

    # Check general prefix
    return options.has_valid_general_prefix_dir()

# Make each of the computer user folders inside the general prefix; False at the first that fails
def _make_general_prefix_folders(options, verbose, pretend_run, exit_on_failure):
    return fileops.make_directories(
        dirs = [paths.join_paths(options.get_general_prefix_dir(), folder) for folder in config.computer_user_folders],
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# Create a Wine prefix linked to the general prefix, or a Sandboxie prefix for any other type
def _create_linked_prefix_of_type(options, verbose, pretend_run, exit_on_failure):

    # Setup wine prefix
    if options.is_wine_prefix():
        return _create_linked_wine_prefix(
            options = options,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    # Setup sandboxie prefix
    return create_sandboxie_prefix(
        options = options,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# Create a Wine prefix whose user profile is a link to the general prefix
def _create_linked_wine_prefix(options, verbose, pretend_run, exit_on_failure):

    # Create wine prefix
    success = create_wine_prefix(
        options = options,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return False

    # Link prefix
    return fileops.create_symlink(
        src = options.get_general_prefix_dir(),
        dest = prefixlayout.get_wine_user_profile_path(options),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# Link each existing "from" path to its "to" path under the C drive; False at the first link that fails
def _link_other_paths(other_links, prefix_c_drive, verbose, pretend_run, exit_on_failure):
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
    success = _create_linked_or_basic_prefix(
        options = options,
        linked_prefix = linked_prefix,
        other_links = other_links,
        clean_existing = clean_existing,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return False
    return _record_prefix_locations(options)

# Create the prefix linked to the general prefix when linked_prefix is set, otherwise standalone
def _create_linked_or_basic_prefix(options, linked_prefix, other_links, clean_existing, verbose, pretend_run, exit_on_failure):
    if linked_prefix:
        return create_linked_prefix(
            options = options,
            other_links = other_links,
            clean_existing = clean_existing,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
    return create_basic_prefix(
        options = options,
        clean_existing = clean_existing,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# Store the created prefix's user profile and C drive on the options; False when either is missing
def _record_prefix_locations(options):

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

# Kill everything running under Wine with wineserver -k, then any wineserver left
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
