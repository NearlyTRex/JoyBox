# Imports
import os
import os.path

# Local imports
from joybox import config
from joybox import validation
from joybox import paths
from joybox import fileops
from joybox import serialization
from joybox import command

# Entry for one .reg block: its first line as the bracketless key, the rest as its value lines
def parse_registry_entry(token):
    registry_key = ""
    registry_values = []
    for line_num, line in enumerate(token.split("\n")):
        if line_num == 0:
            registry_key = line.strip("[]")
        else:
            registry_values.append(line)
    registry_entry = {}
    registry_entry["key"] = registry_key.strip()
    registry_entry["value"] = "\n".join(registry_values)
    return registry_entry

# Whether a key starts with no ignore prefix and, when keep prefixes are given, with one of them
def is_registry_key_kept(registry_key, ignore_keys, keep_keys):
    if any(registry_key.startswith(ignore_key) for ignore_key in ignore_keys):
        return False
    if keep_keys:
        return any(registry_key.startswith(keep_key) for keep_key in keep_keys)
    return True

# Parse a UTF-16 .reg file into its header and key/value entries, filtered by key prefix; empty on a pretend run
def read_registry_file(
    registry_file,
    ignore_keys = (),
    keep_keys = (),
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get registry text
    registry_text = ""
    if not pretend_run:
        registry_text = serialization.read_text_file(
            registry_file, encoding = "utf-16", verbose = verbose, exit_on_failure = exit_on_failure)
        if registry_text is None:
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

        # Read entry
        registry_entry = parse_registry_entry(token)
        if len(registry_entry["key"]) == 0:
            continue

        # Add entry unless ignored or not kept
        if is_registry_key_kept(registry_entry["key"], ignore_keys, keep_keys):
            registry["entries"].append(registry_entry)

    # Return results
    return registry

# Write a header and entries back out as a UTF-16 .reg file in the platform's line endings
def write_registry_file(
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

    # Write registry file, in the platform's line endings as regedit writes them
    return serialization.write_text_file(
        registry_file, registry_text, encoding = "utf-16", newline = None,
        verbose = verbose, pretend_run = pretend_run, exit_on_failure = exit_on_failure)

# Export one key with reg export through the options' prefix; True when the .reg file appears
def export_registry_file(
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
    registry_options.set_is_shell(True)
    registry_options.set_blocking_processes(["reg"])

    # Run registry command
    code = command.run_returncode_command(
        cmd = registry_cmd,
        options = registry_options,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if code != 0:
        return False

    # Check result
    return os.path.exists(registry_file)

# Load a .reg file with reg import through the options' prefix; True when reg exits cleanly
def import_registry_file(
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
    code = command.run_returncode_command(
        cmd = registry_cmd,
        options = registry_options,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if code != 0:
        return False

    # Assume successful
    return True

# Export one key to temp_reg_file and read back the entries the filters allow; None when the export fails
def export_registry_key_data(
    temp_reg_file,
    registry_key,
    options,
    ignore_keys,
    keep_keys,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    success = export_registry_file(
        registry_file = temp_reg_file,
        registry_key = registry_key,
        options = options,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return None
    return read_registry_file(
        registry_file = temp_reg_file,
        ignore_keys = ignore_keys,
        keep_keys = keep_keys,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# Header and filtered entries of every export key, each exported to its own .reg in tmp_dir; None when an export fails
def collect_registry_data(
    tmp_dir,
    export_keys,
    options,
    ignore_keys,
    keep_keys,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    registry_data = {}
    registry_data["header"] = ""
    registry_data["entries"] = []
    for key_index, base_key in enumerate(export_keys):

        # Export and read registry key
        key_data = export_registry_key_data(
            temp_reg_file = paths.join_paths(tmp_dir, "temp%d.reg" % key_index),
            registry_key = base_key,
            options = options,
            ignore_keys = ignore_keys,
            keep_keys = keep_keys,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if key_data is None:
            return None

        # Collect entries
        if not registry_data["header"]:
            registry_data["header"] = key_data.get("header", "")
        registry_data["entries"] += key_data.get("entries", [])
    return registry_data

# Export each key to a temporary .reg, keep the entries the filters allow, and write them into one .reg file
def backup_user_registry(
    registry_file,
    options,
    export_keys = (),
    ignore_keys = None,
    keep_keys = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get keys
    ignore_keys = [] if ignore_keys is None else ignore_keys
    keep_keys = [] if keep_keys is None else keep_keys

    # Check params
    validation.assert_is_valid_path(registry_file, "registry_file")

    # Export each key to its own file in a temporary directory, collect the entries, and drop the exports
    with fileops.temporary_directory(verbose = verbose, pretend_run = pretend_run) as tmp_dir_result:
        if not tmp_dir_result:
            return False
        registry_data = collect_registry_data(
            tmp_dir = tmp_dir_result,
            export_keys = export_keys,
            options = options,
            ignore_keys = ignore_keys,
            keep_keys = keep_keys,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if registry_data is None:
            return False

        # Write new pruned registry file
        return write_registry_file(
            registry_file = registry_file,
            registry_data = registry_data,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

# Import the setup or game prefix's saved .reg file; True with nothing to do when none is saved
def restore_registry(
    options,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get registry dir
    registry_dir = options.get_prefix_user_profile_registry_dir()
    if not registry_dir:
        return False

    # Get registry file
    registry_file = ""
    if options.get_prefix_name() == config.PrefixType.SETUP:
        registry_file = paths.join_paths(registry_dir, config.REGISTRY_FILENAME_SETUP)
    elif options.get_prefix_name() == config.PrefixType.GAME:
        registry_file = paths.join_paths(registry_dir, config.REGISTRY_FILENAME_GAME)
    if not paths.does_path_exist(registry_file):
        return True

    # Import registry file
    return import_registry_file(
        registry_file = registry_file,
        options = options,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# Registry file, export keys and ignore keys for the setup or game prefix; None for any other prefix
def get_registry_backup_targets(options, registry_dir):
    if options.get_prefix_name() == config.PrefixType.SETUP:
        return (
            paths.join_paths(registry_dir, config.REGISTRY_FILENAME_SETUP),
            config.registry_export_keys_setup,
            config.ignored_registry_keys_setup)
    if options.get_prefix_name() == config.PrefixType.GAME:
        return (
            paths.join_paths(registry_dir, config.REGISTRY_FILENAME_GAME),
            config.registry_export_keys_game,
            config.ignored_registry_keys_game)
    return None

# Save the requested keys from the setup or game prefix into its profile's .reg file; False for any other prefix
def backup_registry(
    options,
    registry_keys = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get registry keys
    registry_keys = [] if registry_keys is None else registry_keys

    # Ignore empty keys
    if not registry_keys:
        return True

    # Get registry dir
    registry_dir = options.get_prefix_user_profile_registry_dir()
    if not registry_dir:
        return False

    # Get registry file, export keys, and ignore keys
    backup_targets = get_registry_backup_targets(options, registry_dir)
    if not backup_targets:
        return False
    registry_file, registry_export_keys, registry_ignore_keys = backup_targets

    # Backup registry
    return backup_user_registry(
        registry_file = registry_file,
        options = options,
        export_keys = registry_export_keys,
        ignore_keys = registry_ignore_keys,
        keep_keys = registry_keys,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
