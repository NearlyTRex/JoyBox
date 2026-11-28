# Preset runs: expanding a preset option group into one tool command per
# platform it names, and running each in turn.

# Imports

# Local imports
from joybox import config
from joybox import command
from joybox import environment
from joybox import logger

# The command a preset tool run starts with: the tool's path, plus --verbose and
# --exit_on_failure when set
def get_preset_base_command(preset_tool_type, verbose = False, exit_on_failure = False):
    base_cmd = [
        environment.get_command_path(preset_tool_type.val())
    ]
    if verbose:
        base_cmd += ["--verbose"]
    if exit_on_failure:
        base_cmd += ["--exit_on_failure"]
    return base_cmd

# The backup tool commands a preset option group expands to: one per subcategory when it
# names a supercategory, category and subcategories, else one for its category or its
# supercategory alone; none when it names no supercategory
def get_backup_tool_preset_commands(base_cmd, preset_options, output_path, skip_existing = False, skip_identical = False):
    base_cmd = base_cmd + ["-o", output_path]
    if skip_existing:
        base_cmd += ["--skip_existing"]
    if skip_identical:
        base_cmd += ["--skip_identical"]
    if "supercategory" not in preset_options:
        return []
    supercategory_cmd = base_cmd + ["-u", preset_options["supercategory"]]
    if "category" not in preset_options:
        return [supercategory_cmd]
    category_cmd = supercategory_cmd + ["-c", preset_options["category"]]
    if "subcategories" not in preset_options:
        return [category_cmd]
    return [category_cmd + ["-s", subcategory] for subcategory in preset_options["subcategories"]]

# Run each preset command, logging any that fails; True when all succeed
def run_preset_commands(preset_cmds, verbose = False, pretend_run = False, exit_on_failure = False):
    success = True
    for preset_cmd in preset_cmds:
        code = command.run_returncode_command(
            cmd = preset_cmd,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if code != 0:
            logger.log_error("Preset command failed with code %d" % code)
            success = False
    return success

# Run a preset tool once per platform a preset option group names, returning whether every
# run succeeded; False, logged, for a tool presets do not support
def run_presets(
    preset_tool_type,
    preset_option_group_type,
    output_path,
    skip_existing = False,
    skip_identical = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    preset_options = config.presets_option_groups[preset_option_group_type]
    base_cmd = get_preset_base_command(preset_tool_type, verbose = verbose, exit_on_failure = exit_on_failure)
    if preset_tool_type != config.PresetToolType.BACKUP_TOOL:
        logger.log_error("Unsupported preset tool %s" % preset_tool_type)
        return False
    preset_cmds = get_backup_tool_preset_commands(
        base_cmd,
        preset_options,
        output_path,
        skip_existing = skip_existing,
        skip_identical = skip_identical)
    return run_preset_commands(
        preset_cmds,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
