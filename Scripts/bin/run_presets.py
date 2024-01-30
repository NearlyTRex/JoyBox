#!/usr/bin/env python3

# Imports
import os, os.path
import sys
import argparse

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.append(lib_folder)
import config
import command
import environment
import system
import setup

# Parse arguments
parser = argparse.ArgumentParser(description="Run tool presets.")
parser.add_argument("-t", "--preset_tool",
    choices=[
        "backup_tool"
    ], help="Tool to use"
)
parser.add_argument("-p", "--preset_type", choices=config.preset_types, help="Preset type")
parser.add_argument("-o", "--output_path", type=str, default=".", help="Output path")
parser.add_argument("-e", "--skip_existing", action="store_true", help="Skip existing files")
parser.add_argument("-i", "--skip_identical", action="store_true", help="Skip identical files")
parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose mode")
parser.add_argument("-x", "--exit_on_failure", action="store_true", help="Enable exit on failure mode")
args, unknown = parser.parse_known_args()

# Get output path
output_path = os.path.realpath(args.output_path)
if not os.path.exists(output_path):
    system.LogError("Output path '%s' does not exist" % args.output_path)
    sys.exit(-1)

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Get preset options
    preset_options = config.presets_options[args.preset_type]

    # Backup tool
    if args.preset_tool == "backup_tool":

        # Check preset options
        has_supercategory = "supercategory" in preset_options
        has_category = "category" in preset_options
        has_subcategories = "subcategories" in preset_options

        # Create base command
        base_cmd = [
            os.path.join(environment.GetScriptsBinDir(), args.preset_tool + environment.GetScriptsCommandExtension()),
            "-t", "Storage",
            "-o", output_path
        ]
        if args.skip_existing:
            base_cmd += ["--skip_existing"]
        if args.skip_identical:
            base_cmd += ["--skip_identical"]
        if args.verbose:
            base_cmd += ["--verbose"]
        if args.exit_on_failure:
            base_cmd += ["--exit_on_failure"]

        # Create preset commands
        preset_cmds = []
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
            command.RunCheckedCommand(
                cmd = preset_cmd,
                verbose = args.verbose,
                exit_on_failure = args.exit_on_failure)

# Start
main()
