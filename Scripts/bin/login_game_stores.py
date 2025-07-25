#!/usr/bin/env python3

# Imports
import os, os.path
import sys

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.append(lib_folder)
import config
import environment
import system
import gameinfo
import collection
import arguments
import setup

# Parse arguments
parser = arguments.ArgumentParser(description = "Login stores.")
parser.add_game_supercategory_argument()
parser.add_game_category_argument()
parser.add_game_subcategory_argument()
parser.add_enum_argument(
    args = ("-m", "--generation_mode"),
    arg_type = config.GenerationModeType,
    default = config.GenerationModeType.STANDARD,
    description = "Generation mode")
parser.add_common_arguments()
args, unknown = parser.parse_known_args()

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Manually specify all parameters
    if args.generation_mode == config.GenerationModeType.CUSTOM:
        if not args.game_category:
            system.LogError("Game category is required for custom mode", quit_program = True)
        if not args.game_subcategory:
            system.LogError("Game subcategory is required for custom mode", quit_program = True)
        success = collection.LoginGameStore(
            game_supercategory = args.game_supercategory,
            game_category = args.game_category,
            game_subcategory = args.game_subcategory,
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure)
        if not success:
            system.LogError(
                message = "Login of store failed!",
                game_supercategory = args.game_supercategory,
                game_category = args.game_category,
                game_subcategory = args.game_subcategory,
                quit_program = True)

    # Automatic according to standard layout
    elif args.generation_mode == config.GenerationModeType.STANDARD:
        for game_supercategory in parser.get_selected_supercategories():
            for game_category, game_subcategories in parser.get_selected_subcategories().items():
                for game_subcategory in game_subcategories:
                        success = collection.LoginGameStore(
                            game_supercategory = game_supercategory,
                            game_category = game_category,
                            game_subcategory = game_subcategory,
                            verbose = args.verbose,
                            pretend_run = args.pretend_run,
                            exit_on_failure = args.exit_on_failure)
                        if not success:
                            system.LogError(
                                message = "Login of store failed!",
                                game_supercategory = game_supercategory,
                                game_category = game_category,
                                game_subcategory = game_subcategory,
                                quit_program = True)

# Start
main()
