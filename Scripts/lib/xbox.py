# Imports
import os
import os.path
import sys

# Local imports
import command
import fileops
import programs
import system
import logger
import paths

# Extract Xbox ISO
def ExtractXboxISO(
    iso_file,
    extract_dir,
    delete_original = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get tool
    extract_tool = None
    if programs.is_tool_installed("ExtractXIso"):
        extract_tool = programs.get_tool_program("ExtractXIso")
    if not extract_tool:
        logger.log_error("ExtractXIso was not found")
        return False

    # Get extract command
    extract_cmd = [
        extract_tool,
        "-x",
        "-d", extract_dir,
        iso_file
    ]

    # Run extract command
    code = command.run_returncode_command(
        cmd = extract_cmd,
        options = command.create_command_options(
            blocking_processes = [extract_tool]),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if code != 0:
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

# Rewrite Xbox ISO
def RewriteXboxISO(
    iso_file,
    delete_original = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get tool
    extract_tool = None
    if programs.is_tool_installed("ExtractXIso"):
        extract_tool = programs.get_tool_program("ExtractXIso")
    if not extract_tool:
        logger.log_error("ExtractXIso was not found")
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
    code = command.run_returncode_command(
        cmd = rewrite_cmd,
        options = command.create_command_options(
            blocking_processes = [extract_tool]),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if code != 0:
        logger.log_error("Unable to rewrite xbox iso '%s'" % iso_file)
        return False

    # Must have worked
    return True
