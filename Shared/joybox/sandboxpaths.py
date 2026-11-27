# Paths across a prefix's boundary: translating between the paths a program
# sees inside it and the real ones, and moving or copying files out of it.

# Imports
import os
import os.path

# Local imports
from joybox import config
from joybox import validation
from joybox import fileops
from joybox import filebulk
from joybox import commandbase
from joybox import programs
from joybox import paths
from joybox import sandbox
from joybox import prefixlayout

###########################################################

# Get program prefix name
def get_program_prefix_name(program_name):
    if programs.is_program_name_tool(program_name):
        return config.PrefixType.TOOL
    elif programs.is_program_name_emulator(program_name):
        return config.PrefixType.EMULATOR
    return None

# Translate path if necessary
def translate_path_if_necessary(path, program_exe, program_name):

    # Check params
    validation.assert_is_valid_path(path, "path")
    validation.assert_is_non_empty_string(program_exe, "program_exe")
    validation.assert_is_non_empty_string(program_name, "program_name")

    # Check if prefix is necessary first
    should_run_via_wine = sandbox.should_be_run_via_wine(program_exe)
    should_run_via_sandboxie = sandbox.should_be_run_via_sandboxie(program_exe)
    if not should_run_via_wine and not should_run_via_sandboxie:
        return path

    # Get prefix options
    options = commandbase.create_command_options(
        prefix_name = get_program_prefix_name(program_name),
        is_wine_prefix = should_run_via_wine,
        is_sandboxie_prefix = should_run_via_sandboxie)

    # Translate path
    return translate_real_path_to_virtual_path(
        path = path,
        options = options)

# Translate virtual path to real path
def translate_virtual_path_to_real_path(
    path,
    options):

    # Check params
    validation.assert_is_valid_path(path, "path")

    # Check prefix type
    if not options.is_prefix():
        return path

    # Check prefix
    if not options.get_prefix_dir():
        options = options.copy()
        options.set_prefix_dir(prefixlayout.get_prefix(options))
    if not options.get_prefix_dir():
        return None

    # Get path info
    path_info = prefixlayout.get_prefix_path_info(
        path = path,
        options = options,
        is_virtual_path = True,
        is_real_path = False)
    if not path_info:
        return None

    # Return real path
    return path_info["real"]

# Translate real path to virtual path
def translate_real_path_to_virtual_path(
    path,
    options):

    # Check params
    validation.assert_is_valid_path(path, "path")

    # Check prefix type
    if not options.is_prefix():
        return path

    # Check prefix
    if not options.get_prefix_dir():
        options = options.copy()
        options.set_prefix_dir(prefixlayout.get_prefix(options))
    if not options.get_prefix_dir():
        return None

    # Get path info
    path_info = prefixlayout.get_prefix_path_info(
        path = path,
        options = options,
        is_virtual_path = False,
        is_real_path = True)
    if not path_info:
        return None

    # Return virtual path
    return path_info["virtual"]

# Transfer from sandbox
def transfer_from_sandbox(
    path,
    options,
    keep_in_sandbox = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Check params
    validation.assert_is_valid_path(path, "path")

    # Get real path
    real_path = translate_virtual_path_to_real_path(
        path = path,
        options = options)
    if not real_path:
        return

    # Ignore if paths are the same
    if os.path.normpath(path) == os.path.normpath(real_path):
        return

    # Ignore if not present in sandbox
    if not paths.does_path_exist(real_path):
        return

    # Transfer from sandbox
    if keep_in_sandbox:
        if paths.is_path_directory(real_path):
            filebulk.copy_contents(
                src = real_path,
                dest = path,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
        else:
            fileops.copy_file_or_directory(
                src = real_path,
                dest = path,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
    else:
        if paths.is_path_directory(real_path):
            filebulk.move_contents(
                src = real_path,
                dest = path,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
        else:
            fileops.move_file_or_directory(
                src = real_path,
                dest = path,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
