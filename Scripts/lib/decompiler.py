# Imports
import os
import sys

# Local imports
import config
import system
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

    # Resolve script paths
    resolved = dict(preset)
    repo_path = os.path.expanduser(preset.get("repo_path", ""))
    resolved["repo_path"] = os.path.abspath(repo_path)
    resolved["project_dir_abs"] = os.path.join(resolved["repo_path"], preset.get("project_dir", ""))
    if "scripts" in resolved:
        resolved_scripts = {}
        for name, script_config in resolved["scripts"].items():
            resolved_script = dict(script_config)
            resolved_script["script_path_abs"] = os.path.join(
                resolved["repo_path"],
                script_config.get("script_path", "")
            )
            if "default_args" in script_config:
                resolved_args = []
                for arg in script_config["default_args"]:
                    if not arg.startswith("-") and "/" in arg:
                        resolved_args.append(os.path.join(resolved["repo_path"], arg))
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

def RunHeadlessScript(
    project_dir,
    project_name,
    program_name,
    script_path,
    script_name,
    script_args = None,
    noanalysis = True,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get tool
    analyze_tool = None
    if programs.IsToolInstalled("GhidraHeadless"):
        analyze_tool = programs.GetToolProgram("GhidraHeadless")
    if not analyze_tool:
        system.LogError("Ghidra headless analyzer was not found")
        return False

    # Validate paths exist
    if not os.path.isdir(project_dir):
        system.LogError("Project directory not found: %s" % project_dir)
        return False
    if not os.path.isdir(script_path):
        system.LogError("Script path not found: %s" % script_path)
        return False

    # Build command
    cmd = [
        analyze_tool,
        project_dir,
        project_name,
        "-process", program_name,
        "-scriptPath", script_path,
        "-postScript", script_name
    ]

    # Add script arguments
    if script_args:
        if isinstance(script_args, list):
            cmd.extend(script_args)
        else:
            cmd.append(script_args)

    # Add noanalysis flag
    if noanalysis:
        cmd.insert(cmd.index("-scriptPath"), "-noanalysis")

    # Log what we're doing
    if verbose:
        system.LogInfo("Running Ghidra headless:")
        system.LogInfo("  Project: %s/%s" % (project_dir, project_name))
        system.LogInfo("  Program: %s" % program_name)
        system.LogInfo("  Script: %s/%s" % (script_path, script_name))
        if script_args:
            system.LogInfo("  Args: %s" % script_args)

    # Run command
    code = command.RunReturncodeCommand(
        cmd = cmd,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return (code == 0)

def RunHeadlessScriptFromPreset(
    preset_name,
    script_name,
    script_args = None,
    noanalysis = True,
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
    return RunHeadlessScript(
        project_dir = preset["project_dir_abs"],
        project_name = preset["project_name"],
        program_name = preset["program_name"],
        script_path = script_config["script_path_abs"],
        script_name = script_config["script_name"],
        script_args = script_args,
        noanalysis = noanalysis,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
