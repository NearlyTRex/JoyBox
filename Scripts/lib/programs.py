# Imports
import os, os.path
import sys

# Local imports
import config
import command
import environment
import system
import tools
import emulators

###########################################################

# Get config value
def GetConfigValue(program_config, program_name, program_key, program_platform = None):
    if not program_platform:
        program_platform = environment.GetCurrentPlatform()
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
def GetPathConfigValue(program_config, base_dir, program_name, program_key, program_platform = None):
    program_path = GetConfigValue(program_config, program_name, program_key, program_platform)
    if program_path:
        if os.path.exists(program_path):
            return program_path
        return os.path.join(base_dir, program_path)
    return None

# Get program
def GetProgram(program_config, base_dir, program_name, program_platform = None):
    return GetPathConfigValue(program_config, base_dir, program_name, "program", program_platform)

###########################################################

# Get program install dir
def GetProgramInstallDir(program_name, program_platform = None):
    if IsProgramNameTool(program_name, program_platform):
        return os.path.join(environment.GetToolsRootDir(), program_name, program_platform)
    elif IsProgramNameEmulator(program_name, program_platform):
        return os.path.join(environment.GetEmulatorsRootDir(), program_name, program_platform)
    return None

# Get program backup dir
def GetProgramBackupDir(program_name, program_platform = None):
    if IsProgramNameTool(program_name, program_platform):
        return environment.GetLockerProgramToolDir(program_name, program_platform)
    elif IsProgramNameEmulator(program_name, program_platform):
        return environment.GetLockerGamingEmulatorBinariesDir(program_name, program_platform)
    return None

# Get library install dir
def GetLibraryInstallDir(library_name, library_platform = None):
    if library_platform:
        return os.path.join(environment.GetToolsRootDir(), library_name, library_platform)
    else:
        return os.path.join(environment.GetToolsRootDir(), library_name)

# Get library backup dir
def GetLibraryBackupDir(library_name, library_platform = None):
    if library_platform:
        return os.path.join(environment.GetLockerProgramToolDir(library_name), library_platform)
    else:
        return environment.GetLockerProgramToolDir(library_name)

# Determine if program should be installed
def ShouldProgramBeInstalled(program_name, program_platform = None):

    # Get default platform if none specified
    if not program_platform:
        program_platform = environment.GetCurrentPlatform()

    # Get program path
    program_path = None
    if IsProgramNameTool(program_name, program_platform):
        program_path = GetProgram(GetToolConfig(), environment.GetToolsRootDir(), program_name, program_platform)
    elif IsProgramNameEmulator(program_name, program_platform):
        program_path = GetProgram(GetEmulatorConfig(), environment.GetEmulatorsRootDir(), program_name, program_platform)

    # Check program path
    if not program_path:
        return False
    if program_platform == "linux" and not environment.IsLinuxPlatform():
        return False
    if os.path.exists(program_path):
        return False
    return True

# Determine if library should be installed
def ShouldLibraryBeInstalled(library_name):
    return system.IsDirectoryEmpty(GetLibraryInstallDir(library_name))

# Determine if program is installed
def IsProgramInstalled(program_name, program_platform = None):
    if IsProgramNameTool(program_name, program_platform):
        return command.IsRunnableCommand(GetToolProgram(program_name, program_platform))
    elif IsProgramNameEmulator(program_name, program_platform):
        return command.IsRunnableCommand(GetEmulatorProgram(program_name, program_platform))
    return False

###########################################################

# Get tools
def GetTools():
    return tools.GetToolList()

# Get emulators
def GetEmulators():
    return emulators.GetEmulatorList()

# Get tool config
def GetToolConfig():
    merged_config = {}
    for tool in tools.GetToolList():
        merged_config.update(tool.GetConfig())
    return merged_config

# Get emulator config
def GetEmulatorConfig():
    merged_config = {}
    for emulator in emulators.GetEmulatorList():
        merged_config.update(emulator.GetConfig())
    return merged_config

###########################################################

# Get tool program
def GetToolProgram(tool_name, tool_platform = None):
    return GetProgram(GetToolConfig(), environment.GetToolsRootDir(), tool_name, tool_platform)

# Get emulator program
def GetEmulatorProgram(emulator_name, emulator_platform = None):
    return GetProgram(GetEmulatorConfig(), environment.GetEmulatorsRootDir(), emulator_name, emulator_platform)

# Get tool program dir
def GetToolProgramDir(tool_name, tool_platform = None):
    return system.GetFilenameDirectory(GetToolProgram(tool_name, tool_platform))

# Get emulator program dir
def GetEmulatorProgramDir(emulator_name, emulator_platform = None):
    return system.GetFilenameDirectory(GetEmulatorProgram(emulator_name, emulator_platform))

# Get tool config value
def GetToolConfigValue(tool_name, tool_key, tool_platform = None):
    return GetConfigValue(GetToolConfig(), tool_name, tool_key, tool_platform)

# Get emulator config value
def GetEmulatorConfigValue(emulator_name, emulator_key, emulator_platform = None):
    return GetConfigValue(GetEmulatorConfig(), emulator_name, emulator_key, emulator_platform)

# Get tool path config value
def GetToolPathConfigValue(tool_name, tool_key, tool_platform = None):
    return GetPathConfigValue(GetToolConfig(), environment.GetToolsRootDir(), tool_name, tool_key, tool_platform)

# Get emulator path config value
def GetEmulatorPathConfigValue(emulator_name, emulator_key, emulator_platform = None):
    return GetPathConfigValue(GetEmulatorConfig(), environment.GetEmulatorsRootDir(), emulator_name, emulator_key, emulator_platform)

# Derive tool name from program path
def DeriveToolNameFromProgramPath(program_path, tool_platform = None):
    if not program_path or not os.path.exists(program_path):
        return None
    for tool_name in GetToolConfig().keys():
        tool_path = GetToolProgram(tool_name, tool_platform)
        if tool_path and os.path.normpath(tool_path) == os.path.normpath(program_path):
            return tool_name
    return None

# Derive emulator name from program path
def DeriveEmulatorNameFromProgramPath(program_path, emulator_platform = None):
    if not program_path or not os.path.exists(program_path):
        return None
    for emulator_name in GetEmulatorConfig().keys():
        emulator_path = GetEmulatorProgram(emulator_name, emulator_platform)
        if emulator_path and os.path.normpath(emulator_path) == os.path.normpath(program_path):
            return emulator_name
    return None

###########################################################

# Determine if program name is a tool
def IsProgramNameTool(program_name, program_platform = None):
    tool_program = GetProgram(GetToolConfig(), environment.GetToolsRootDir(), program_name, program_platform)
    return tool_program is not None

# Determine if program name is an emulator
def IsProgramNameEmulator(program_name, program_platform = None):
    emulator_program = GetProgram(GetEmulatorConfig(), environment.GetEmulatorsRootDir(), program_name, program_platform)
    return emulator_program is not None

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

# Determine if program path is a tool
def IsProgramPathTool(program_path, program_platform = None):
    tool_name = DeriveToolNameFromProgramPath(program_path, program_platform)
    return tool_name is None

# Determine if program path is an emulator
def IsProgramPathEmulator(program_path, program_platform = None):
    emulator_name = DeriveEmulatorNameFromProgramPath(program_path, program_platform)
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
    tool_name = DeriveToolNameFromProgramPath(program_path, program_platform)
    if not tool_name:
        return False
    tool_config = GetToolConfigValue(tool_name, "run_sandboxed", program_platform)
    if tool_config:
        return tool_config
    return False

# Determine if program path is a sandboxed emulator
def IsProgramPathSandboxedEmulator(program_path, program_platform = None):
    emulator_name = DeriveEmulatorNameFromProgramPath(program_path, program_platform)
    if not emulator_name:
        return False
    emulator_config = GetEmulatorConfigValue(emulator_name, "run_sandboxed", program_platform)
    if emulator_config:
        return emulator_config
    return False

###########################################################
