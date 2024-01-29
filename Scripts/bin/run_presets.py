#!/usr/bin/env python3

# Imports
import os, os.path
import sys
import argparse

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.append(lib_folder)
import command
import environment
import system
import setup

# Parse arguments
parser = argparse.ArgumentParser(description="Run tool presets.")
parser.add_argument("-t", "--tool",
    choices=[
        "backup_tool"
    ], help="Tool to use"
)
parser.add_argument("-p", "--preset",
    choices=[
        "Backup_NintendoGen",
        "Backup_NintendoSwitch",
        "Backup_SonyGen",
        "Backup_SonyPSN"
    ], help="Tool preset to use"
)
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

    # Scripts
    backup_tool_file_bin = os.path.join(environment.GetScriptsBinDir(), "backup_tool" + environment.GetScriptsCommandExtension())

    # Options
    backup_tool_options = {}

    # Backup tool
    if args.tool == "backup_tool":

        # Backup_NintendoGen
        if args.preset == "Backup_NintendoGen":
            backup_tool_options = {
                "supercategory": "Roms",
                "category": "Nintendo",
                "subcategories": [
                    "Nintendo 3DS",
                    "Nintendo 3DS Apps",
                    "Nintendo 3DS eShop",
                    "Nintendo 64",
                    "Nintendo DS",
                    "Nintendo DSi",
                    "Nintendo Famicom",
                    "Nintendo Game Boy",
                    "Nintendo Game Boy Advance",
                    "Nintendo Game Boy Advance e-Reader",
                    "Nintendo Game Boy Color",
                    "Nintendo Gamecube",
                    "Nintendo NES",
                    "Nintendo SNES",
                    "Nintendo Super Famicom",
                    "Nintendo Super Game Boy",
                    "Nintendo Super Game Boy Color",
                    "Nintendo Virtual Boy",
                    "Nintendo Wii",
                    "Nintendo Wii U",
                    "Nintendo Wii U eShop"
                ]
            }

        # Backup_NintendoSwitch
        elif args.preset == "Backup_NintendoSwitch":
            backup_tool_options = {
                "supercategory": "Roms",
                "category": "Nintendo",
                "subcategories": [
                    "Nintendo Switch",
                    "Nintendo Switch eShop"
                ]
            }

        # Backup_SonyGen
        elif args.preset == "Backup_SonyGen":
            backup_tool_options = {
                "supercategory": "Roms",
                "category": "Sony",
                "subcategories": [
                    "Sony PlayStation",
                    "Sony PlayStation 2",
                    "Sony PlayStation Portable",
                    "Sony PlayStation Portable Video",
                    "Sony PlayStation Vita"
                ]
            }

        # Backup_SonyPSN
        elif args.preset == "Backup_SonyPSN":
            backup_tool_options = {
                "supercategory": "Roms",
                "category": "Sony",
                "subcategories": [
                    "Sony PlayStation Network - PlayStation 3",
                    "Sony PlayStation Network - PlayStation 4",
                    "Sony PlayStation Network - PlayStation Portable",
                    "Sony PlayStation Network - PlayStation Portable Minis",
                    "Sony PlayStation Network - PlayStation Vita"
                ]
            }

        # Run each preset
        for subcategory in backup_tool_options["subcategories"]:

            # Get backup tool command
            backup_tool_cmd = [
                backup_tool_file_bin,
                "-t", "Storage",
                "-u", backup_tool_options["supercategory"],
                "-c", backup_tool_options["category"],
                "-s", subcategory,
                "-o", output_path
            ]
            if args.skip_existing:
                backup_tool_cmd += ["--skip_existing"]
            if args.skip_identical:
                backup_tool_cmd += ["--skip_identical"]
            if args.verbose:
                backup_tool_cmd += ["--verbose"]
            if args.exit_on_failure:
                backup_tool_cmd += ["--exit_on_failure"]

            # Run backup tool
            command.RunCheckedCommand(
                cmd = backup_tool_cmd,
                verbose = args.verbose,
                exit_on_failure = args.exit_on_failure)

# Start
main()
