# Imports
import os, os.path
import sys

# Local imports
import config
import system
import validation
import logger
import paths
import environment
import fileops
import command
import programs
import sandbox

# Read registry file
def ReadRegistryFile(
    registry_file,
    ignore_keys = [],
    keep_keys = [],
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get registry text
    registry_text = ""
    try:
        if verbose:
            logger.log_info("Reading registry file '%s'" % registry_file)
        if not pretend_run:
            with open(registry_file, "r", encoding="utf-16") as file:
                registry_text = file.read()
    except Exception as e:
        if exit_on_failure:
            logger.log_error("Unable to read registry file '%s'" % registry_file)
            logger.log_error(e, quit_program = True)
        return {}

    # Create registry container
    registry = {}
    registry["header"] = ""
    registry["entries"] = []

    # Parse registry text
    for token in registry_text.split("\n\n"):

        # Read header
        if token.startswith("Windows Registry Editor"):
            registry["header"] = token.strip()
            continue

        # Create entry
        registry_key = ""
        registry_values = []

        # Read entry
        line_num = 0
        for line in token.split("\n"):
            if line_num == 0:
                registry_key = line.strip("[]")
            else:
                registry_values.append(line)
            line_num += 1

        # Clean entry
        registry_key = registry_key.strip()
        if len(registry_key) == 0:
            continue

        # Check if entry should be ignored
        should_ignore = False
        for ignore_key in ignore_keys:
            if registry_key.startswith(ignore_key):
                should_ignore = True
                break
        if should_ignore:
            continue

        # Create entry
        registry_entry = {}
        registry_entry["key"] = registry_key
        registry_entry["value"] = "\n".join(registry_values)

        # Add entry
        if len(keep_keys):
            should_keep = False
            for keep_key in keep_keys:
                if registry_key.startswith(keep_key):
                    should_keep = True
                    break
            if should_keep:
                registry["entries"].append(registry_entry)
        else:
            registry["entries"].append(registry_entry)

    # Return results
    return registry

# Write registry file
def WriteRegistryFile(
    registry_file,
    registry_data,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Create registry text
    registry_text = ""
    registry_text += "%s\n" % registry_data["header"]
    registry_text += "\n"
    for entry in registry_data["entries"]:
        registry_text += "[%s]\n" % entry["key"]
        if len(entry["value"]):
            registry_text += "%s\n" % entry["value"]
        registry_text += "\n"

    # Write registry file
    try:
        if verbose:
            logger.log_info("Writing registry file '%s'" % registry_file)
        if not pretend_run:
            with open(registry_file, "w", encoding="utf-16") as file:
                file.write(registry_text)
        return True
    except Exception as e:
        if exit_on_failure:
            logger.log_error("Unable to write registry file '%s'" % registry_file)
            logger.log_error(e, quit_program = True)
        return False
    return False

# Export registry file
def ExportRegistryFile(
    registry_file,
    registry_key,
    options,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Check params
    validation.assert_is_valid_path(registry_file, "registry_file")
    validation.assert_is_non_empty_string(registry_key, "registry_key")

    # Get registry command
    registry_cmd = [
        "reg",
        "export",
        "\"%s\"" % registry_key,
        registry_file,
        "/y"
    ]

    # Get registry options
    registry_options = options.copy()
    registry_options.set_force_prefix(True)
    registry_options.set_shell(True)
    registry_options.set_blocking_processes(["reg"])

    # Run registry command
    code = command.RunReturncodeCommand(
        cmd = registry_cmd,
        options = registry_options,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if code != 0:
        return False

    # Check result
    return os.path.exists(registry_file)

# Import registry file
def ImportRegistryFile(
    registry_file,
    options,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Check params
    validation.assert_path_exists(registry_file, "registry_file")

    # Get registry command
    registry_cmd = [
        "reg",
        "import", registry_file
    ]

    # Get registry options
    registry_options = options.copy()
    registry_options.set_force_prefix(True)
    registry_options.set_blocking_processes(["reg"])

    # Run registry command
    code = command.RunReturncodeCommand(
        cmd = registry_cmd,
        options = registry_options,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if code != 0:
        return False

    # Assume successful
    return True

# Backup registry
def BackupUserRegistry(
    registry_file,
    options,
    export_keys = [],
    ignore_keys = [],
    keep_keys = [],
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Check params
    validation.assert_is_valid_path(registry_file, "registry_file")

    # Create temporary directory
    tmp_dir_success, tmp_dir_result = fileops.create_temporary_directory(
        verbose = verbose,
        pretend_run = pretend_run)
    if not tmp_dir_success:
        return False

    # Temporary files
    temp_reg_file = paths.join_paths(tmp_dir_result, "temp.reg")

    # Export current user registry
    for base_key in export_keys:
        success = ExportRegistryFile(
            registry_file = temp_reg_file,
            registry_key = base_key,
            options = options,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return False

    # Read registry file
    registry_data = ReadRegistryFile(
        registry_file = temp_reg_file,
        ignore_keys = ignore_keys,
        keep_keys = keep_keys,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Write new pruned registry file
    return WriteRegistryFile(
        registry_file = registry_file,
        registry_data = registry_data,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
