# Imports
import os

# Local imports
from joybox import config
from joybox import logger
from joybox import environment
from joybox import programs
from joybox import command
from joybox import commandbase

###########################################################

# The named Ghidra project preset from config.decompiler_presets; None when unknown
def get_decompiler_preset(preset_name):
    return config.decompiler_presets.get(preset_name)

# Every preset name config.decompiler_presets defines
def get_decompiler_preset_names():
    return list(config.decompiler_presets.keys())

# Names of the scripts a preset defines; empty when the preset is unknown or has none
def get_preset_script_names(preset_name):
    preset = get_decompiler_preset(preset_name)
    if preset and "scripts" in preset:
        return list(preset["scripts"].keys())
    return []

# A preset script's settings by name; None when the preset or script is unknown
def get_preset_script(preset_name, script_name):
    preset = get_decompiler_preset(preset_name)
    if preset and "scripts" in preset:
        return preset["scripts"].get(script_name)
    return None

# A copy of the preset with its repository, project directory, script paths and path-like
# default arguments made absolute under the repositories root; None when unknown
def resolve_preset_paths(preset_name):

    # Get preset
    preset = get_decompiler_preset(preset_name)
    if not preset:
        return None

    # Resolve repository path
    resolved = dict(preset)
    repo_path = os.path.join(environment.get_repositories_root_dir(), preset.get("repository", ""))
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

# (name, description) for every preset, with "No description" when one has none
def list_presets():
    presets = []
    for preset_name in get_decompiler_preset_names():
        preset = get_decompiler_preset(preset_name)
        desc = preset.get("description", "No description")
        presets.append((preset_name, desc))
    return presets

# (name, description) for each script in a preset; None when the preset is unknown
def list_preset_scripts(preset_name):
    preset = get_decompiler_preset(preset_name)
    if not preset:
        return None
    scripts = []
    for script_name, script_config in preset.get("scripts", {}).items():
        desc = script_config.get("description", "No description")
        scripts.append((script_name, desc))
    return scripts

###########################################################

# Open the Ghidra GUI through pyghidra -g in the venv Python; False when Python or Ghidra
# is missing or it exits nonzero
def launch_program(verbose = False, pretend_run = False, exit_on_failure = False):

    # Get Python tool
    python_tool = programs.find_tool_program("PythonVenvPython")
    if not python_tool:
        return False

    # Get Ghidra install directory for pyghidra
    ghidra_install_dir = programs.get_library_install_dir("Ghidra", "lib")
    if not ghidra_install_dir or not os.path.isdir(ghidra_install_dir):
        logger.log_error("Ghidra installation not found at: %s" % ghidra_install_dir)
        return False

    # Get launch command - use pyghidra -g to launch Ghidra GUI with Python support
    launch_cmd = [
        python_tool,
        "-m",
        "pyghidra",
        "-g"
    ]

    # Log what we're doing
    if verbose:
        logger.log_info("Launching Ghidra with PyGhidra:")
        logger.log_info("  Python: %s" % python_tool)
        logger.log_info("  Ghidra: %s" % ghidra_install_dir)

    # Create command options with Ghidra install dir environment variable
    cmd_options = commandbase.create_command_options()
    cmd_options.set_env_var("GHIDRA_INSTALL_DIR", ghidra_install_dir)

    # Run launch command
    code = command.run_returncode_command(
        cmd = launch_cmd,
        options = cmd_options,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return code == 0

# Run a PyGhidra script headless against a program in a Ghidra project, passing the project,
# program and extra arguments; False when a tool, the script or the project is missing
def run_script(
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
    python_tool = programs.find_tool_program("PythonVenvPython")
    if not python_tool:
        return False

    # Get Ghidra install directory for pyghidra
    ghidra_install_dir = programs.get_library_install_dir("Ghidra", "lib")
    if not ghidra_install_dir or not os.path.isdir(ghidra_install_dir):
        logger.log_error("Ghidra installation not found at: %s" % ghidra_install_dir)
        return False

    # Get the full script path
    script_file = os.path.join(script_path, script_name)

    # Validate script exists
    if not os.path.isfile(script_file):
        logger.log_error("Script not found: %s" % script_file)
        return False

    # Validate project directory exists
    if not os.path.isdir(project_dir):
        logger.log_error("Project directory not found: %s" % project_dir)
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
        logger.log_info("Running PyGhidra script:")
        logger.log_info("  Project: %s/%s" % (project_dir, project_name))
        logger.log_info("  Program: %s" % program_name)
        logger.log_info("  Script: %s" % script_file)
        logger.log_info("  Ghidra: %s" % ghidra_install_dir)
        if script_args:
            logger.log_info("  Args: %s" % script_args)

    # Create command options with Ghidra install dir environment variable
    cmd_options = commandbase.create_command_options()
    cmd_options.set_env_var("GHIDRA_INSTALL_DIR", ghidra_install_dir)

    # Force headless AWT for the PyGhidra JVM. Running scripts is a headless batch
    # job, so Ghidra must never open an X11 display. Without this,
    # PyGhidraProjectManager init connects to $DISPLAY and dies when the X server
    # is unreachable or out of client slots ("Maximum number of clients reached").
    # The interactive GUI path is intentionally not touched since it needs a display.
    existing_java_opts = cmd_options.get_env_var("JAVA_TOOL_OPTIONS") or ""
    headless_opt = "-Djava.awt.headless=true"
    if headless_opt not in existing_java_opts:
        cmd_options.set_env_var(
            "JAVA_TOOL_OPTIONS",
            (existing_java_opts + " " + headless_opt).strip())

    # Run command
    code = command.run_returncode_command(
        cmd = cmd,
        options = cmd_options,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return code == 0

# Run one of a preset's scripts with its resolved paths, falling back to its default arguments
# and preset-level program name; False when the preset or script is unknown
def run_script_from_preset(
    preset_name,
    script_name,
    script_args = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get resolved preset
    preset = resolve_preset_paths(preset_name)
    if not preset:
        logger.log_error("Preset not found: %s" % preset_name)
        logger.log_info("Available presets: %s" % ", ".join(get_decompiler_preset_names()))
        return False

    # Get script config
    script_config = preset.get("scripts", {}).get(script_name)
    if not script_config:
        logger.log_error("Script '%s' not found in preset '%s'" % (script_name, preset_name))
        logger.log_info("Available scripts: %s" % ", ".join(get_preset_script_names(preset_name)))
        return False

    # Use default args if none provided
    if script_args is None:
        script_args = script_config.get("default_args_abs", script_config.get("default_args"))

    # Run the script. A script config may override the preset-level program_name
    # (e.g. per-program export targets); otherwise the preset default is used.
    return run_script(
        project_dir = preset["project_dir_abs"],
        project_name = preset["project_name"],
        program_name = script_config.get("program_name", preset["program_name"]),
        script_path = script_config["script_path_abs"],
        script_name = script_config["script_name"],
        script_args = script_args,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
