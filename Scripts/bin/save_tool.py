#!/usr/bin/env python3

# Imports
import os, os.path
import sys

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.append(lib_folder)
import config
import system
import saves
import arguments
import setup

# Parse arguments
parser = arguments.ArgumentParser(description = "Save tool.")
parser.add_input_path_argument()
parser.add_enum_argument(
    args = ("-a", "--action"),
    arg_type = config.SaveActionType,
    default = config.SaveActionType.PACK,
    description = "Save action type")
parser.add_game_category_arguments()
parser.add_game_name_argument()
parser.add_common_arguments()
args, unknown = parser.parse_known_args()

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Pack saves
    if args.action == config.SaveActionType.PACK:
        saves.PackSave(
            game_category = args.game_category,
            game_subcategory = args.game_subcategory,
            game_name = args.game_name,
            save_dir = args.input_path,
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure)

    # Unpack saves
    elif args.action == config.SaveActionType.UNPACK:
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
