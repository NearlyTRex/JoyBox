# Imports
import os, os.path
import sys

# Local imports
import config
import command
import environment
import paths
import system
import tools
import emulators

###########################################################

# Get config value
def get_config_value(program_config, program_name, program_key, program_platform = None):
    if not program_platform:
        program_platform = environment.get_current_platform()
    program_value = None
    try:
        program_value = program_config[program_name][program_key]
    except:
        pass
    if isinstance(program_value, dict):
        if program_platform in program_value.keys():
            return program_value[program_platform]
        else:
            return program_value
    else:
        return program_value

# Get path config value
def get_path_config_value(program_config, base_dir, program_name, program_key, program_platform = None):
    program_path = get_config_value(program_config, program_name, program_key, program_platform)
    if program_path:
        if os.path.exists(program_path):
            return program_path
        return paths.join_paths(base_dir, program_path)
    return None

# Get program
def get_program(program_config, base_dir, program_name, program_platform = None):
    return get_path_config_value(program_config, base_dir, program_name, "program", program_platform)

###########################################################

# Get program install dir
def get_program_install_dir(program_name, program_platform = None):
    if is_program_name_tool(program_name, program_platform):
        return paths.join_paths(environment.get_tools_root_dir(), program_name, program_platform)
    elif is_program_name_emulator(program_name, program_platform):
        return paths.join_paths(environment.get_emulators_root_dir(), program_name, program_platform)
    return None

# Get program backup dir
def get_program_backup_dir(program_name, program_platform = None):
    if is_program_name_tool(program_name, program_platform):
        return environment.get_locker_program_tool_dir(program_name, program_platform)
    elif is_program_name_emulator(program_name, program_platform):
        return environment.get_locker_gaming_emulator_binaries_dir(program_name, program_platform)
    return None

# Get library install dir
def get_library_install_dir(library_name, library_platform = None):
    if library_platform:
        return paths.join_paths(environment.get_tools_root_dir(), library_name, library_platform)
    else:
        return paths.join_paths(environment.get_tools_root_dir(), library_name)

# Get library backup dir
def get_library_backup_dir(library_name, library_platform = None):
    if library_platform:
        return paths.join_paths(environment.get_locker_program_tool_dir(library_name), library_platform)
    else:
        return environment.get_locker_program_tool_dir(library_name)

# Determine if program should be installed
def should_program_be_installed(program_name, program_platform = None):

    # Get default platform if none specified
    if not program_platform:
        program_platform = environment.get_current_platform()

    # Get program path
    program_path = None
    if is_program_name_tool(program_name, program_platform):
        program_path = get_program(get_tool_config(), environment.get_tools_root_dir(), program_name, program_platform)
    elif is_program_name_emulator(program_name, program_platform):
        program_path = get_program(get_emulator_config(), environment.get_emulators_root_dir(), program_name, program_platform)

    # Check program path
    if not program_path:
        return False
    if program_platform == "linux" and not environment.is_linux_platform():
        return False
    if os.path.exists(program_path):
        return False
    return True

# Determine if library should be installed
def should_library_be_installed(library_name):
    return paths.is_directory_empty(get_library_install_dir(library_name))

# Determine if program is installed
def is_program_installed(program_name, program_platform = None):
    if is_program_name_tool(program_name, program_platform):
        return command.is_runnable_command(get_tool_program(program_name, program_platform))
    elif is_program_name_emulator(program_name, program_platform):
        return command.is_runnable_command(get_emulator_program(program_name, program_platform))
    return False

###########################################################

# Get tools
def get_tools():
    return tools.get_tool_list()

# Get emulators
def get_emulators():
    return emulators.get_emulator_list()

# Get emulator by platform
def get_emulator_by_platform(emulator_platform):
    for emulator in get_emulators():
        if emulator_platform in emulator.get_platforms():
            return emulator
    return None

# Get tool config
def get_tool_config():
    merged_config = {}
    for tool in tools.get_tool_list():
        merged_config.update(tool.get_config())
    return merged_config

# Get emulator config
def get_emulator_config():
    merged_config = {}
    for emulator in emulators.get_emulator_list():
        merged_config.update(emulator.get_config())
    return merged_config

###########################################################

# Get tool program
def get_tool_program(tool_name, tool_platform = None):
    return get_program(get_tool_config(), environment.get_tools_root_dir(), tool_name, tool_platform)

# Get emulator program
def get_emulator_program(emulator_name, emulator_platform = None):
    return get_program(get_emulator_config(), environment.get_emulators_root_dir(), emulator_name, emulator_platform)

# Get tool program dir
def get_tool_program_dir(tool_name, tool_platform = None):
    return paths.get_filename_directory(get_tool_program(tool_name, tool_platform))

# Get emulator program dir
def get_emulator_program_dir(emulator_name, emulator_platform = None):
    return paths.get_filename_directory(get_emulator_program(emulator_name, emulator_platform))

# Get tool config value
def get_tool_config_value(tool_name, tool_key, tool_platform = None):
    return get_config_value(get_tool_config(), tool_name, tool_key, tool_platform)

# Get emulator config value
def get_emulator_config_value(emulator_name, emulator_key, emulator_platform = None):
    return get_config_value(get_emulator_config(), emulator_name, emulator_key, emulator_platform)

# Get tool path config value
def get_tool_path_config_value(tool_name, tool_key, tool_platform = None):
    return get_path_config_value(get_tool_config(), environment.get_tools_root_dir(), tool_name, tool_key, tool_platform)

# Get emulator path config value
def get_emulator_path_config_value(emulator_name, emulator_key, emulator_platform = None):
    return get_path_config_value(get_emulator_config(), environment.get_emulators_root_dir(), emulator_name, emulator_key, emulator_platform)

# Derive tool name from program path
def derive_tool_name_from_program_path(program_path, tool_platform = None):
    if not program_path or not os.path.exists(program_path):
        return None
    for tool_name in get_tool_config().keys():
        tool_path = get_tool_program(tool_name, tool_platform)
        if tool_path and os.path.normpath(tool_path) == os.path.normpath(program_path):
            return tool_name
    return None

# Derive emulator name from program path
def derive_emulator_name_from_program_path(program_path, emulator_platform = None):
    if not program_path or not os.path.exists(program_path):
        return None
    for emulator_name in get_emulator_config().keys():
        emulator_path = get_emulator_program(emulator_name, emulator_platform)
        if emulator_path and os.path.normpath(emulator_path) == os.path.normpath(program_path):
            return emulator_name
    return None

###########################################################

# Determine if program name is a tool
def is_program_name_tool(program_name, program_platform = None):
    tool_program = get_program(get_tool_config(), environment.get_tools_root_dir(), program_name, program_platform)
    return tool_program is not None

# Determine if program name is an emulator
def is_program_name_emulator(program_name, program_platform = None):
    emulator_program = get_program(get_emulator_config(), environment.get_emulators_root_dir(), program_name, program_platform)
    return emulator_program is not None

# Determine if tool is installed
def is_tool_installed(tool_name, tool_platform = None):
    tool_program = get_tool_program(tool_name, tool_platform)
    if tool_program:
        return os.path.exists(tool_program)
    return False

# Determine if emulator is installed
def is_emulator_installed(emulator_name, emulator_platform = None):
    emulator_program = get_emulator_program(emulator_name, emulator_platform)
    if emulator_program:
        return os.path.exists(emulator_program)
    return False

# Determine if program path is a tool
def is_program_path_tool(program_path, program_platform = None):
    tool_name = derive_tool_name_from_program_path(program_path, program_platform)
    return tool_name is None

# Determine if program path is an emulator
def is_program_path_emulator(program_path, program_platform = None):
    emulator_name = derive_emulator_name_from_program_path(program_path, program_platform)
    return emulator_name is None

# Determine if program name is a sandboxed tool
def is_program_name_sandboxed_tool(program_name, program_platform = None):
    tool_config = get_tool_config_value(program_name, "run_sandboxed", program_platform)
    return tool_config is not None

# Determine if program name is a sandboxed emulator
def is_program_name_sandboxed_emulator(program_name, program_platform = None):
    emulator_config = get_emulator_config_value(program_name, "run_sandboxed", program_platform)
    return emulator_config is not None

# Determine if program path is a sandboxed tool
def is_program_path_sandboxed_tool(program_path, program_platform = None):
    tool_name = derive_tool_name_from_program_path(program_path, program_platform)
    if not tool_name:
        return False
    tool_config = get_tool_config_value(tool_name, "run_sandboxed", program_platform)
    if tool_config:
        return tool_config
    return False

# Determine if program path is a sandboxed emulator
def is_program_path_sandboxed_emulator(program_path, program_platform = None):
    emulator_name = derive_emulator_name_from_program_path(program_path, program_platform)
    if not emulator_name:
        return False
    emulator_config = get_emulator_config_value(emulator_name, "run_sandboxed", program_platform)
    if emulator_config:
        return emulator_config
    return False

###########################################################
