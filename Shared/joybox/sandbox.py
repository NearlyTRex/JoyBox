# Imports
import copy

# Local imports
from joybox import config
from joybox import fileops
from joybox import commandbase
from joybox import programs
from joybox import paths
from joybox import prefixlayout
from joybox import cmdline
from joybox import platform_info
from joybox import gui

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

# Path to the Wine executable from the tool programs
def get_wine_command():
    return programs.get_tool_program("Wine")

# Path to the Sandboxie launcher from the tool programs
def get_sandboxie_command():
    return programs.get_tool_program("Sandboxie")

###########################################################

# Processes to wait on after a Wine run: the wineserver
def get_wine_blocking_processes():
    return [
        programs.get_tool_program("WineServer")
    ]

# Processes to wait on after a Sandboxie run: its launcher, ini, rpcss and dcomlaunch services
def get_sandboxie_blocking_processes():
    return [
        programs.get_tool_program("Sandboxie"),
        programs.get_tool_program("SandboxieIni"),
        programs.get_tool_program("SandboxieRpcss"),
        programs.get_tool_program("SandboxieDcomlaunch")
    ]

# The initial processes plus the Wine or Sandboxie ones the options' prefix needs, as a new list
def get_blocking_processes(options, initial_processes = None):
    initial_processes = [] if initial_processes is None else initial_processes
    blocking_processes = copy.deepcopy(initial_processes)
    if options.is_wine_prefix():
        blocking_processes += get_wine_blocking_processes()
    elif options.is_sandboxie_prefix():
        blocking_processes += get_sandboxie_blocking_processes()
    return blocking_processes

###########################################################

# Copy DLLs into the Wine prefix: 32-bit ones to system32 on a 32-bit prefix, else 64 to system32 and 32 to syswow64
def install_wine_dlls(
    options,
    dlls_32 = (),
    dlls_64 = (),
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    wine_c_drive = prefixlayout.get_wine_real_drive_path(options, "c")
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

# Copy DLLs into the options' prefix; only Wine prefixes take them, Sandboxie is a no-op
def install_dlls(
    options,
    dlls_32 = None,
    dlls_64 = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    dlls_32 = [] if dlls_32 is None else dlls_32
    dlls_64 = [] if dlls_64 is None else dlls_64

    # Only a wine prefix takes dlls; Sandboxie needs no libraries installed
    if options.is_wine_prefix():
        install_wine_dlls(
            options = options,
            dlls_32 = dlls_32,
            dlls_64 = dlls_64,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

###########################################################

# Set Wine's blocking processes and env vars on the options, and link the cwd into the prefix when mapped
def setup_wine_prefix_environment(
    new_options,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

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
            dest = prefixlayout.get_real_drive_path(
                options = new_options,
                drive = config.DRIVE_PREFIX_CWD),
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

# Copies of cmd and options with Wine env vars, cwd drive mapping and blocking processes set for the prefix
# Unchanged when the options are not a prefix
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
        setup_wine_prefix_environment(new_options, verbose = verbose, pretend_run = pretend_run, exit_on_failure = exit_on_failure)

    # Modify for sandboxie
    else:

        # Add blocking processes
        new_options.add_blocking_processes(get_sandboxie_blocking_processes())

    # Return results
    return (new_cmd, new_options)

# Wine launcher, in a virtual desktop when asked, or Sandboxie launcher for the prefix's box, hidden for tools
def get_prefix_command_starter(options):
    if options.is_wine_prefix():
        new_cmd = [get_wine_command()]
        if options.use_virtual_desktop():
            new_cmd += ["explorer", "/desktop=" + options.get_desktop_dimensions()]
        return new_cmd
    new_cmd = [
        get_sandboxie_command(),
        "/box:%s" % options.get_prefix_name().val()
    ]
    if options.get_prefix_name() == config.PrefixType.TOOL:
        new_cmd += ["/hide_window"]
    return new_cmd

# Target and args of a .lnk, setting the options' cwd to its own; shows an error popup when either does not exist
def get_link_target_command(lnk_path, options):
    info = fileops.get_link_info(
        lnk_path = lnk_path,
        lnk_base_path = options.get_lnk_base_path())
    has_valid_target = paths.does_path_exist(info["target"])
    has_valid_cwd = paths.does_path_exist(info["cwd"])
    if not has_valid_target or not has_valid_cwd:
        gui.display_error_popup(
            title_text = "Unable to resolve LNK file",
            message_text = "Unable to resolve LNK file %s to an actual target" % lnk_path)
    options.set_cwd(info["cwd"])
    return [info["target"]] + info["args"]

# Wrap cmd to run under Wine or Sandboxie, resolving .lnk targets and running .bat via cmd /c in Sandboxie
# Returns the new command and options; unchanged when the options are not a prefix
def setup_prefix_command(
    cmd,
    options = None):

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
    new_cmd = get_prefix_command_starter(new_options)

    # Adjust command based on executable type
    if orig_cmd_starter.endswith(".lnk"):
        new_cmd += get_link_target_command(orig_cmd_starter, new_options)
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

###########################################################
