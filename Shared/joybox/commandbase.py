# Imports
import os

# Local imports
from joybox import cmdline
from joybox import config
from joybox import logger
from joybox import environment
from joybox import commandoptions
from joybox import programs

# Create command options
def create_command_options(*args, **kwargs):
    return commandoptions.CommandOptions(*args, **kwargs)

###########################################################

# Get starter command
def get_starter_command(cmd):
    cmd_list = cmdline.create_command_list(cmd)
    if len(cmd_list) == 0:
        return ""
    return cmd_list[0]

# Check if only starter command
def is_only_starter_command(cmd):
    cmd_list = cmdline.create_command_list(cmd)
    return len(cmd_list) == 1

###########################################################

# Check if command type is found
def is_command_type_found(cmd, cmd_exts = (), search_start = 0, search_len = -1):
    cmd_list = cmdline.create_command_list(cmd)
    for cmd_index, cmd_segment in enumerate(cmd_list):
        is_found = False
        for ext in cmd_exts:
            if cmd_segment.lower().endswith(ext):
                is_found = True
                break
        is_in_range = True
        if 0 <= search_start < len(cmd_list) and search_len > 0:
            is_in_range = search_start <= cmd_index < search_start + search_len
        if is_found and is_in_range:
            return True
    return False

###########################################################

# Check if cached game command
def is_cached_game_command(cmd):
    starter_cmd = os.path.normpath(get_starter_command(cmd)).lower()
    cached_dir = os.path.normpath(environment.get_cache_gaming_root_dir()).lower()
    return starter_cmd.startswith(cached_dir)

# Check if local script command
def is_local_script_command(cmd):
    starter_cmd = os.path.normpath(get_starter_command(cmd)).lower()
    commands_dir = os.path.normpath(environment.get_commands_dir()).lower()
    return starter_cmd.startswith(commands_dir)

# Check if local program command
def is_local_program_command(cmd):
    starter_cmd = get_starter_command(cmd)
    is_tool = programs.is_program_path_tool(starter_cmd)
    is_emulator = programs.is_program_path_emulator(starter_cmd)
    return is_tool or is_emulator

# Check if local sandboxed program command
def is_local_sandboxed_program_command(cmd):
    starter_cmd = get_starter_command(cmd)
    is_sandboxed_tool = programs.is_program_path_sandboxed_tool(starter_cmd)
    is_sandboxed_emulator = programs.is_program_path_sandboxed_emulator(starter_cmd)
    return is_sandboxed_tool or is_sandboxed_emulator

# Check if windows executable command
def is_windows_executable_command(cmd):
    return is_command_type_found(
        cmd = get_starter_command(cmd),
        cmd_exts = config.WindowsProgramFileType.cvalues())

# Check if powershell command
def is_powershell_command(cmd):
    starter_cmd = os.path.normpath(get_starter_command(cmd)).lower()
    return (
        starter_cmd.startswith("powershell") or
        starter_cmd.endswith("powershell") or
        starter_cmd.endswith("powershell.exe")
    )

# Check if appimage command
def is_appimage_command(cmd):
    starter_cmd = os.path.normpath(get_starter_command(cmd)).lower()
    return starter_cmd.endswith("appimage")

###########################################################

# Print command
def print_command(cmd):
    masked_cmd = cmdline.mask_sensitive_args(cmd)
    if isinstance(masked_cmd, str):
        logger.log_info(masked_cmd)
    if isinstance(masked_cmd, list):
        logger.log_info(" ".join(masked_cmd))
