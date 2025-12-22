#!/usr/bin/env python3

# Imports
import os, os.path
import sys

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.append(lib_folder)
import config
import system
import environment
import decompiler
import arguments
import setup
import logger

# Parse arguments
parser = arguments.ArgumentParser(description = "Decompiler tool.")
parser.add_enum_argument(
    args = ("-a", "--action"),
    arg_type = config.DecompilerActionType,
    default = config.DecompilerActionType.LAUNCH_PROGRAM,
    description = "Decompiler action type")
parser.add_string_argument(args = ("-n", "--project_name"), description = "Project name")
parser.add_string_argument(args = ("-l", "--project_language"), default = "x86:LE:32:watcom", description = "Project language")
parser.add_string_argument(args = ("-c", "--project_cspec"), default = "watcomcpp", description = "Project compiler spec")
parser.add_input_path_argument(args = ("-r", "--project_dir"), description = "Project directory")
parser.add_string_argument(args = ("-g", "--program_name"), description = "Program name")
parser.add_string_argument(args = ("--preset",), description = "Preset name (e.g., NocturneDecomp)")
parser.add_string_argument(args = ("--script",), description = "Script name from preset (e.g., export_annotations)")
parser.add_input_path_argument(args = ("--script_path",), description = "Script directory path (manual mode)")
parser.add_string_argument(args = ("--script_name",), description = "Script filename (manual mode)")
parser.add_string_argument(args = ("--script_args",), description = "Arguments to pass to the script")
parser.add_boolean_argument(args = ("--list_presets",), description = "List available presets and exit")
parser.add_boolean_argument(args = ("--list_scripts",), description = "List available scripts for a preset and exit")
parser.add_common_arguments()
args = parser.parse_args()

# Main
def main():

    # Check requirements
    setup.check_requirements()

    # Setup logging
    logger.setup_logging()

    # List presets
    if args.list_presets:
        logger.log_info("Available presets:")
        for preset_name, desc in decompiler.ListPresets():
            logger.log_info("  %s - %s" % (preset_name, desc))
        return

    # List scripts
    if args.list_scripts:
        if args.preset:
            scripts = decompiler.ListPresetScripts(args.preset)
            if scripts is None:
                logger.log_error("Preset not found: %s" % args.preset)
                return
            logger.log_info("Available scripts for '%s':" % args.preset)
            for script_name, desc in scripts:
                logger.log_info("  %s - %s" % (script_name, desc))
        else:
            for preset_name, preset_desc in decompiler.ListPresets():
                logger.log_info("%s:" % preset_name)
                for script_name, desc in decompiler.ListPresetScripts(preset_name):
                    logger.log_info("  %s - %s" % (script_name, desc))
        return

    # Launch program
    if args.action == config.DecompilerActionType.LAUNCH_PROGRAM:
        decompiler.LaunchProgram(
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure)
        return

    # Run script
    if args.action == config.DecompilerActionType.RUN_SCRIPT:

        # Preset mode
        if args.preset:
            if not args.script:
                logger.log_error("--script is required when using --preset")
                logger.log_info("Use --list_scripts --preset %s to see available scripts" % args.preset)
                return
            decompiler.RunScriptFromPreset(
                preset_name = args.preset,
                script_name = args.script,
                script_args = args.script_args,
                verbose = args.verbose,
                pretend_run = args.pretend_run,
                exit_on_failure = args.exit_on_failure)
            return

        # Manual mode
        project_dir = parser.get_checked_path("project_dir")
        script_path = parser.get_checked_path("script_path")
        if not all([project_dir, args.project_name, args.program_name, script_path, args.script_name]):
            logger.log_error("Manual mode requires: --project_dir, --project_name, --program_name, --script_path, --script_name")
            logger.log_info("Or use preset mode with: --preset <name> --script <script>")
            logger.log_info("Use --list_presets to see available presets")
            return
        decompiler.RunScript(
            project_dir = project_dir,
            project_name = args.project_name,
            program_name = args.program_name,
            script_path = script_path,
            script_name = args.script_name,
            script_args = args.script_args,
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure)

# Start
if __name__ == "__main__":
    system.run_main(main)
