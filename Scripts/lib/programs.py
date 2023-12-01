# Imports
import os, os.path
import sys
import getpass

# Custom imports
lib_folder = os.path.realpath(os.path.dirname(__file__))
sys.path.append(lib_folder)
import environment
import system
import tools
import emulators

# Get config value
def GetConfigValue(config, app_name, app_key, platform):
    app_value = None
    try:
        app_value = config[app_name][app_key]
    except:
        pass
    if isinstance(app_value, dict):
        if platform in app_value.keys():
            return app_value[platform]
        else:
            return app_value
    else:
        return app_value

# Get path config value
def GetPathConfigValue(config, base_dir, app_name, app_key, platform):
    app_path = GetConfigValue(config, app_name, app_key, platform)
    if app_path:
        return os.path.join(base_dir, app_path)
    return None

# Get program
def GetProgram(config, base_dir, app_name, platform = None):
    if not platform:
        platform = environment.GetCurrentPlatform()
    return GetPathConfigValue(config, base_dir, app_name, "program", platform)

# Get tool program
def GetToolProgram(tool_name, tool_platform = None):
    if not tool_platform:
        tool_platform = environment.GetCurrentPlatform()
    return GetProgram(tools.GetConfig(), tools.GetBaseDirectory(), tool_name, tool_platform)

# Get emulator program
def GetEmulatorProgram(emulator_name, emulator_platform = None):
    if not emulator_platform:
        emulator_platform = environment.GetCurrentPlatform()
    return GetProgram(emulators.GetConfig(), emulators.GetBaseDirectory(), emulator_name, emulator_platform)

# Get tool program dir
def GetToolProgramDir(tool_name, tool_platform = None):
    return system.GetFilenameDirectory(GetToolProgram(tool_name, tool_platform))

# Get emulator program dir
def GetEmulatorProgramDir(emulator_name, emulator_platform = None):
    return system.GetFilenameDirectory(GetEmulatorProgram(emulator_name, emulator_platform))

# Get tool config value
def GetToolConfigValue(tool_name, app_key, tool_platform = None):
    if not tool_platform:
        tool_platform = environment.GetCurrentPlatform()
    return GetConfigValue(tools.GetConfig(), tool_name, app_key, tool_platform)

# Get emulator config value
def GetEmulatorConfigValue(emulator_name, app_key, emulator_platform = None):
    if not emulator_platform:
        emulator_platform = environment.GetCurrentPlatform()
    return GetConfigValue(emulators.GetConfig(), emulator_name, app_key, emulator_platform)

# Get tool path config value
def GetToolPathConfigValue(tool_name, app_key, tool_platform = None):
    if not tool_platform:
        tool_platform = environment.GetCurrentPlatform()
    return GetPathConfigValue(tools.GetConfig(), tools.GetBaseDirectory(), tool_name, app_key, tool_platform)

# Get emulator path config value
def GetEmulatorPathConfigValue(emulator_name, app_key, emulator_platform = None):
    if not emulator_platform:
        emulator_platform = environment.GetCurrentPlatform()
    return GetPathConfigValue(emulators.GetConfig(), emulators.GetBaseDirectory(), emulator_name, app_key, emulator_platform)

# Get emulator save dir
def GetEmulatorSaveDir(emulator_name, emulator_platform = None, game_platform = None):
    if not emulator_platform:
        emulator_platform = environment.GetCurrentPlatform()
    saves_dir = GetEmulatorPathConfigValue(emulator_name, "save_dir", emulator_platform)
    saves_base_dir = GetEmulatorPathConfigValue(emulator_name, "save_base_dir", emulator_platform)
    save_sub_dirs = GetEmulatorConfigValue(emulator_name, "save_sub_dirs")
    if saves_base_dir and save_sub_dirs and game_platform:
        if game_platform in save_sub_dirs.keys():
            return os.path.join(saves_base_dir, save_sub_dirs[game_platform])
    return saves_dir

# Get emulator save base dir
def GetEmulatorSaveBaseDir(emulator_name, emulator_platform = None):
    if not emulator_platform:
        emulator_platform = environment.GetCurrentPlatform()
    return GetEmulatorPathConfigValue(emulator_name, "save_base_dir", emulator_platform)

# Get emulator config file
def GetEmulatorConfigFile(emulator_name, emulator_platform = None):
    if not emulator_platform:
        emulator_platform = environment.GetCurrentPlatform()
    return GetEmulatorPathConfigValue(emulator_name, "config_file", emulator_platform)

# Get program prefix name
def GetProgramPrefixName(program_name, program_platform = None):
    if IsProgramNameTool(program_name, program_platform):
        return tools.GetPrefixName()
    elif IsProgramNameEmulator(program_name, program_platform):
        return emulators.GetPrefixName()
    return None

# Get program prefix dir
def GetProgramPrefixDir(program_name, program_platform = None):
    if IsProgramNameTool(program_name, program_platform):
        return tools.GetPrefixDir()
    elif IsProgramNameEmulator(program_name, program_platform):
        return emulators.GetPrefixDir()
    return None

# Determine if tool is installed
def IsToolInstalled(tool_name, tool_platform = None):
    tool_program = GetToolProgram(tool_name, tool_platform)
    if tool_program:
        return os.path.exists(tool_program)
    return False

# Determine if emulator is installed
def IsEmulatorInstalled(emulator_name, emulator_platform = None):
    emulator_program = GetEmulatorProgram(emulator_name, emulator_platform)
    if emulator_program:
        return os.path.exists(emulator_program)
    return False

# Derive tool name from program
def DeriveToolNameFromProgram(program_path, tool_platform = None):
    if not tool_platform:
        tool_platform = environment.GetCurrentPlatform()
    if not program_path or not os.path.exists(program_path):
        return None
    for tool_name in tools.GetConfig().keys():
        tool_path = GetToolProgram(tool_name, tool_platform)
        if tool_path and os.path.normpath(tool_path) == os.path.normpath(program_path):
            return tool_name
    return None

# Derive emulator name from program
def DeriveEmulatorNameFromProgram(program_path, emulator_platform = None):
    if not emulator_platform:
        emulator_platform = environment.GetCurrentPlatform()
    if not program_path or not os.path.exists(program_path):
        return None
    for emulator_name in emulators.GetConfig().keys():
        emulator_path = GetEmulatorProgram(emulator_name, emulator_platform)
        if emulator_path and os.path.normpath(emulator_path) == os.path.normpath(program_path):
            return emulator_name
    return None

# Determine if program name is a tool
def IsProgramNameTool(program_name, program_platform = None):
    tool_program = GetToolProgram(program_name, program_platform)
    return tool_program is not None

# Determine if program name is an emulator
def IsProgramNameEmulator(program_name, program_platform = None):
    emulator_program = GetToolProgram(program_name, program_platform)
    return emulator_program is not None

# Determine if program path is a tool
def IsProgramPathTool(program_path, program_platform = None):
    tool_name = DeriveToolNameFromProgram(program_path, program_platform)
    return tool_name is None

# Determine if program path is an emulator
def IsProgramPathEmulator(program_path, program_platform = None):
    emulator_name = DeriveEmulatorNameFromProgram(program_path, program_platform)
    return emulator_name is None

# Determine if program name is a sandboxed tool
def IsProgramNameSandboxedTool(program_name, program_platform = None):
    tool_config = GetToolConfigValue(program_name, "run_sandboxed", program_platform)
    return tool_config is not None

# Determine if program name is a sandboxed emulator
def IsProgramNameSandboxedEmulator(program_name, program_platform = None):
    emulator_config = GetEmulatorConfigValue(program_name, "run_sandboxed", program_platform)
    return emulator_config is not None

# Determine if program path is a sandboxed tool
def IsProgramPathSandboxedTool(program_path, program_platform = None):
    tool_name = DeriveToolNameFromProgram(program_path, program_platform)
    if not tool_name:
        return False
    tool_config = GetToolConfigValue(tool_name, "run_sandboxed", program_platform)
    if tool_config:
        return tool_config
    return False

# Determine if program path is a sandboxed emulator
def IsProgramPathSandboxedEmulator(program_path, program_platform = None):
    emulator_name = DeriveEmulatorNameFromProgram(program_path, program_platform)
    if not emulator_name:
        return False
    emulator_config = GetEmulatorConfigValue(emulator_name, "run_sandboxed", program_platform)
    if emulator_config:
        return emulator_config
    return False
