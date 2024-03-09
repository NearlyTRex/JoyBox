# Imports
import os, os.path
import sys

# Local imports
import config
import system
import environment
import command
import programs
import sandbox

# Read registry file
def ReadRegistryFile(registry_file, ignore_keys = [], keep_keys = []):

    # Check params
    system.AssertPathExists(registry_file, "registry_file")

    # Create registry container
    registry = {}
    registry["header"] = ""
    registry["entries"] = []

    # Open registry file
    with open(registry_file, "r", encoding="utf-16") as file:
        data = file.read()

        # Read registry entries
        for token in data.split("\n\n"):

            # Read header
            if token.startswith("Windows Registry Editor"):
                registry["header"] = token.strip()
                continue

            # Create entry
            registry_key = ""
            registry_value = ""

            # Read entry
            line_num = 0
            for line in token.split("\n"):
                if line_num == 0:
                    registry_key = line.strip("[]")
                else:
                    registry_value += line
                line_num += 1

            # Clean entry
            registry_key = registry_key.strip()
            registry_value = registry_value.strip()
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
            registry_entry["value"] = registry_value

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
def WriteRegistryFile(registry_file, registry_data):

    # Check params
    system.AssertIsValidPath(registry_file, "registry_file")

    # Open registry file
    with open(registry_file, "w", encoding="utf-16") as file:

        # Write header
        file.write("%s\n" % registry_data["header"])
        file.write("\n")

        # Write entries
        for entry in registry_data["entries"]:
            file.write("[%s]\n" % entry["key"])
            if len(entry["value"]):
                file.write("%s\n" % entry["value"])
            file.write("\n")
        return True
    return False

# Export registry file
def ExportRegistryFile(
    registry_file,
    registry_key,
    prefix_dir,
    prefix_name = None,
    verbose = False,
    exit_on_failure = False):

    # Check params
    system.AssertIsValidPath(registry_file, "registry_file")
    system.AssertIsNonEmptyString(registry_key, "registry_key")
    system.AssertPathExists(prefix_dir, "prefix_dir")

    # Get registry command
    registry_cmd = [
        "reg",
        "export",
        "\"%s\"" % registry_key,
        registry_file,
        "/y"
    ]

    # Run registry command
    command.RunBlockingCommand(
        cmd = registry_cmd,
        options = command.CommandOptions(
            prefix_dir = prefix_dir,
            prefix_name = prefix_name,
            is_wine_prefix = environment.IsWinePlatform(),
            is_sandboxie_prefix = environment.IsSandboxiePlatform(),
            force_prefix = True,
            shell = True,
            blocking_processes = ["reg"]),
        verbose = verbose,
        exit_on_failure = exit_on_failure)

    # Check result
    return os.path.exists(registry_file)

# Import registry file
def ImportRegistryFile(
    registry_file,
    prefix_dir,
    prefix_name = None,
    verbose = False,
    exit_on_failure = False):

    # Check params
    system.AssertPathExists(registry_file, "registry_file")

    # Get registry command
    registry_cmd = [
        "reg",
        "import", registry_file
    ]

    # Run registry command
    code = command.RunBlockingCommand(
        cmd = registry_cmd,
        options = command.CommandOptions(
            prefix_dir = prefix_dir,
            prefix_name = prefix_name,
            is_wine_prefix = environment.IsWinePlatform(),
            is_sandboxie_prefix = environment.IsSandboxiePlatform(),
            force_prefix = True,
            blocking_processes = ["reg"]),
        verbose = verbose,
        exit_on_failure = exit_on_failure)
    if code != 0:
        return False

    # Assume successful
    return True

# Backup registry
def BackupUserRegistry(
    registry_file,
    prefix_dir,
    prefix_name = None,
    export_keys = [],
    ignore_keys = [],
    keep_keys = [],
    verbose = False,
    exit_on_failure = False):

    # Create temporary directory
    tmp_dir_success, tmp_dir_result = system.CreateTemporaryDirectory(verbose = verbose)
    if not tmp_dir_success:
        return False

    # Temporary files
    temp_reg_file = os.path.join(tmp_dir_result, "temp.reg")

    # Export current user registry
    for base_key in export_keys:
        success = ExportRegistryFile(
            registry_file = temp_reg_file,
            registry_key = base_key,
            prefix_dir = prefix_dir,
            prefix_name = prefix_name,
            verbose = verbose,
            exit_on_failure = exit_on_failure)
        if not success:
            return False

    # Read registry file
    registry_data = ReadRegistryFile(
        registry_file = temp_reg_file,
        ignore_keys = ignore_keys,
        keep_keys = keep_keys)

    # Write new pruned registry file
    return WriteRegistryFile(
        registry_file = registry_file,
        registry_data = registry_data)
