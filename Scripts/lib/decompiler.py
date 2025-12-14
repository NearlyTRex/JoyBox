# Imports
import os
import sys

# Local imports
import config
import system
import environment
import programs
import command

###########################################################

def GetDecompilerPreset(preset_name):
    return config.decompiler_presets.get(preset_name)

def GetDecompilerPresetNames():
    return list(config.decompiler_presets.keys())

def GetPresetScriptNames(preset_name):
    preset = GetDecompilerPreset(preset_name)
    if preset and "scripts" in preset:
        return list(preset["scripts"].keys())
    return []

def GetPresetScript(preset_name, script_name):
    preset = GetDecompilerPreset(preset_name)
    if preset and "scripts" in preset:
        return preset["scripts"].get(script_name)
    return None

def ResolvePresetPaths(preset_name):

    # Get preset
    preset = GetDecompilerPreset(preset_name)
    if not preset:
        return None

    # Resolve repository path
    resolved = dict(preset)
    repo_path = os.path.join(environment.GetRepositoriesRootDir(), preset.get("repository", ""))
    resolved["repo_path"] = repo_path
    resolved["project_dir_abs"] = os.path.join(repo_path, preset.get("project_dir", ""))

    # Resolve script paths
    if "scripts" in resolved:
        resolved_scripts = {}
        for name, script_config in resolved["scripts"].items():
            resolved_script = dict(script_config)
            resolved_script["script_path_abs"] = os.path.join(
                repo_path,
                script_config.get("script_path", "")
            )
            if "default_args" in script_config:
                resolved_args = []
                for arg in script_config["default_args"]:
                    if not arg.startswith("-") and "/" in arg:
                        resolved_args.append(os.path.join(repo_path, arg))
                    else:
                        resolved_args.append(arg)
                resolved_script["default_args_abs"] = resolved_args
            resolved_scripts[name] = resolved_script
        resolved["scripts"] = resolved_scripts
    return resolved

def ListPresets():
    presets = []
    for preset_name in GetDecompilerPresetNames():
        preset = GetDecompilerPreset(preset_name)
        desc = preset.get("description", "No description")
        presets.append((preset_name, desc))
    return presets

def ListPresetScripts(preset_name):
    preset = GetDecompilerPreset(preset_name)
    if not preset:
        return None
    scripts = []
    for script_name, script_config in preset.get("scripts", {}).items():
        desc = script_config.get("description", "No description")
        scripts.append((script_name, desc))
    return scripts

###########################################################

def LaunchProgram(verbose = False, pretend_run = False, exit_on_failure = False):

    # Get tool
    ghidra_tool = None
    if programs.IsToolInstalled("Ghidra"):
        ghidra_tool = programs.GetToolProgram("Ghidra")
    if not ghidra_tool:
        system.LogError("Ghidra was not found")
        return False

    # Get launch command
    launch_cmd = [
        ghidra_tool
    ]

    # Run launch command
    code = command.RunReturncodeCommand(
        cmd = launch_cmd,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return (code == 0)

def RunScript(
    project_dir,
    project_name,
    program_name,
    script_path,
    script_name,
    script_args = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get tool
    python_tool = None
    if programs.IsToolInstalled("PythonVenvPython"):
        python_tool = programs.GetToolProgram("PythonVenvPython")
    if not python_tool:
        system.LogError("PythonVenvPython was not found")
        return False

    # Get Ghidra install directory for pyghidra
    ghidra_install_dir = programs.GetLibraryInstallDir("Ghidra", "lib")
    if not ghidra_install_dir or not os.path.isdir(ghidra_install_dir):
        system.LogError("Ghidra installation not found at: %s" % ghidra_install_dir)
        return False

    # Get the full script path
    script_file = os.path.join(script_path, script_name)

    # Validate script exists
    if not os.path.isfile(script_file):
        system.LogError("Script not found: %s" % script_file)
        return False

    # Validate project directory exists
    if not os.path.isdir(project_dir):
        system.LogError("Project directory not found: %s" % project_dir)
        return False

    # Build command
    cmd = [
        python_tool,
        script_file,
        project_dir,
        project_name,
        program_name
    ]

    # Add script arguments
    if script_args:
        if isinstance(script_args, list):
            cmd.extend(script_args)
        else:
            cmd.append(script_args)

    # Log what we're doing
    if verbose:
        system.LogInfo("Running PyGhidra script:")
        system.LogInfo("  Project: %s/%s" % (project_dir, project_name))
        system.LogInfo("  Program: %s" % program_name)
        system.LogInfo("  Script: %s" % script_file)
        system.LogInfo("  Ghidra: %s" % ghidra_install_dir)
        if script_args:
            system.LogInfo("  Args: %s" % script_args)

    # Create command options with Ghidra install dir environment variable
    cmd_options = command.CreateCommandOptions()
    cmd_options.set_env_var("GHIDRA_INSTALL_DIR", ghidra_install_dir)

    # Run command
    code = command.RunReturncodeCommand(
        cmd = cmd,
        options = cmd_options,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return (code == 0)

def RunScriptFromPreset(
    preset_name,
    script_name,
    script_args = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get resolved preset
    preset = ResolvePresetPaths(preset_name)
    if not preset:
        system.LogError("Preset not found: %s" % preset_name)
        system.LogInfo("Available presets: %s" % ", ".join(GetDecompilerPresetNames()))
        return False

    # Get script config
    script_config = preset.get("scripts", {}).get(script_name)
    if not script_config:
        system.LogError("Script '%s' not found in preset '%s'" % (script_name, preset_name))
        system.LogInfo("Available scripts: %s" % ", ".join(GetPresetScriptNames(preset_name)))
        return False

    # Use default args if none provided
    if script_args is None:
        script_args = script_config.get("default_args_abs", script_config.get("default_args"))

    # Run the script
    return RunScript(
        project_dir = preset["project_dir_abs"],
        project_name = preset["project_name"],
        program_name = preset["program_name"],
        script_path = script_config["script_path_abs"],
        script_name = script_config["script_name"],
        script_args = script_args,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
