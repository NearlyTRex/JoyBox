#!/usr/bin/env python3

# Imports
import os, os.path
import sys

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.append(lib_folder)
import config
import command
import environment
import system
import arguments
import setup
import logger
import paths

# Parse arguments
parser = arguments.ArgumentParser(description = "Run tool presets.")
parser.add_output_path_argument()
parser.add_enum_argument(
    args = ("-r", "--preset_tool_type"),
    arg_type = config.PresetToolType,
    default = config.PresetToolType.BACKUP_TOOL,
    description = "Preset tool type")
parser.add_enum_argument(
    args = ("-g", "--preset_option_group_type"),
    arg_type = config.PresetOptionGroupType,
    description = "Preset option group type")
parser.add_boolean_argument(args = ("-e", "--skip_existing"), description = "Skip existing files")
parser.add_boolean_argument(args = ("-i", "--skip_identical"), description = "Skip identical files")
parser.add_common_arguments()
args, unknown = parser.parse_known_args()

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Setup logging
    logger.setup_logging()

    # Get output path
    output_path = parser.get_output_path()

    # Get preset options
    preset_options = config.presets_option_groups[args.preset_group_type]

    # Create base command
    base_cmd = [
        paths.join_paths(environment.GetScriptsBinDir(), args.preset_tool_type.val() + environment.GetScriptsCommandExtension())
    ]
    if args.verbose:
        base_cmd += ["--verbose"]
    if args.exit_on_failure:
        base_cmd += ["--exit_on_failure"]

    # Create preset commands
    preset_cmds = []

    # Backup tool
    if args.preset_tool_type == config.PresetToolType.BACKUP_TOOL:

        # Check preset options
        has_supercategory = "supercategory" in preset_options
        has_category = "category" in preset_options
        has_subcategories = "subcategories" in preset_options

        # Update base command
        base_cmd += [
            "-o", output_path
        ]
        if args.skip_existing:
            base_cmd += ["--skip_existing"]
        if args.skip_identical:
            base_cmd += ["--skip_identical"]

        # Add to preset commands
        if has_supercategory and has_category and has_subcategories:
            for subcategory in preset_options["subcategories"]:
                preset_cmds += [
                    base_cmd + [
                        "-u", preset_options["supercategory"],
                        "-c", preset_options["category"],
                        "-s", subcategory
                    ]
                ]
        elif has_supercategory and has_category:
            preset_cmds += [
                base_cmd + [
                    "-u", preset_options["supercategory"],
                    "-c", preset_options["category"]
                ]
            ]
        elif has_supercategory:
            preset_cmds += [
                base_cmd + [
                    "-u", preset_options["supercategory"]
                ]
            ]

    # Run commands
    for preset_cmd in preset_cmds:
        code = command.RunReturncodeCommand(
            cmd = preset_cmd,
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure)
        if code != 0:
            logger.log_error("Preset command failed with code %d" % code)

# Start
if __name__ == "__main__":
    system.run_main(main)
