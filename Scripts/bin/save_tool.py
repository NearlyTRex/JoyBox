#!/usr/bin/env python3

# Imports
import os, os.path
import sys
import argparse

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.append(lib_folder)
import config
import system
import saves
import setup

# Parse arguments
parser = argparse.ArgumentParser(description="Save tool.")
parser.add_argument("-i", "--input_path", type=str, help="Input path")
parser.add_argument("-a", "--action",
    choices=config.SaveActionType.values(),
    default=config.SaveActionType.PACK, help="Save action"
)
parser.add_argument("-c", "--game_category", type=str, help="Game category")
parser.add_argument("-s", "--game_subcategory", type=str, help="Game subcategory")
parser.add_argument("-n", "--game_name", type=str, help="Game name")
parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose mode")
parser.add_argument("-p", "--pretend_run", action="store_true", help="Do a pretend run with no permanent changes")
parser.add_argument("-x", "--exit_on_failure", action="store_true", help="Enable exit on failure mode")
args, unknown = parser.parse_known_args()

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Pack saves
    if args.action == "pack":
        saves.PackSave(
            game_category = args.game_category,
            game_subcategory = args.game_subcategory,
            game_name = args.game_name,
            save_dir = args.input_path,
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure)

    # Unpack saves
    elif args.action == "unpack":
        saves.UnpackSave(
            game_category = args.game_category,
            game_subcategory = args.game_subcategory,
            game_name = args.game_name,
            save_dir = args.input_path,
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure)

# Start
main()
