# Imports
import os
import os.path

# Local imports
from joybox import command
from joybox import commandbase
from joybox import fileops
from joybox import programs
from joybox import logger
from joybox import paths

# Run an extract-xiso command, blocking until the tool exits; whether it exited cleanly
def _run_extract_xiso(extract_tool, cmd, verbose, pretend_run, exit_on_failure):
    code = command.run_returncode_command(
        cmd = cmd,
        options = commandbase.create_command_options(
            blocking_processes = [extract_tool]),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return code == 0

# Unpack an Xbox ISO's files into extract_dir with extract-xiso, optionally deleting the ISO
def extract_xbox_iso(
    iso_file,
    extract_dir,
    delete_original = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get tool
    extract_tool = programs.find_tool_program("ExtractXIso")
    if not extract_tool:
        return False

    # Get extract command
    extract_cmd = [
        extract_tool,
        "-x",
        "-d", extract_dir,
        iso_file
    ]

    # Run extract command
    if not _run_extract_xiso(extract_tool, extract_cmd, verbose, pretend_run, exit_on_failure):
        logger.log_error("Unable to extract xbox iso '%s' to '%s'" % (iso_file, extract_dir))
        return False

    # Clean up
    if delete_original:
        fileops.remove_file(
            src = iso_file,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    # Check result
    return os.path.exists(extract_dir)

# Rebuild an Xbox ISO in place with extract-xiso -r, trimming unused space; -D deletes the original
def rewrite_xbox_iso(
    iso_file,
    delete_original = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get tool
    extract_tool = programs.find_tool_program("ExtractXIso")
    if not extract_tool:
        return False

    # Get rewrite command
    rewrite_cmd = [
        extract_tool,
        "-r",
        "-d", paths.get_filename_directory(iso_file)
    ]
    if delete_original:
        rewrite_cmd += ["-D"]
    rewrite_cmd += [iso_file]

    # Run rewrite command
    if not _run_extract_xiso(extract_tool, rewrite_cmd, verbose, pretend_run, exit_on_failure):
        logger.log_error("Unable to rewrite xbox iso '%s'" % iso_file)
        return False

    # Must have worked
    return True
