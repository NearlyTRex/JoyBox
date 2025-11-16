#!/usr/bin/env python3

# Imports
import os, os.path
import sys

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.append(lib_folder)
import config
import system
import arguments
import setup
import collection
import gameinfo

# Parse arguments
parser = arguments.ArgumentParser(description = "Save tool.")
parser.add_input_path_argument()
parser.add_enum_argument(
    args = ("-a", "--action"),
    arg_type = config.SaveActionType,
    default = config.SaveActionType.PACK,
    description = "Save action type")
parser.add_game_category_argument()
parser.add_game_subcategory_argument()
parser.add_game_name_argument()
parser.add_common_arguments()
args, unknown = parser.parse_known_args()

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Pack saves
    if args.action == config.SaveActionType.PACK:
        for game_supercategory in parser.get_selected_supercategories():
            for game_category, game_subcategories in parser.get_selected_subcategories().items():
                for game_subcategory in game_subcategories:
                    game_names = gameinfo.FindJsonGameNames(
                        game_supercategory,
                        game_category,
                        game_subcategory)
                    for game_name in game_names:
                        game_info = gameinfo.GameInfo(
                            game_supercategory = game_supercategory,
                            game_category = game_category,
                            game_subcategory = game_subcategory,
                            game_name = game_name,
                            verbose = verbose,
                            pretend_run = pretend_run,
                            exit_on_failure = exit_on_failure)
                        success = collection.PackSave(
                            game_info = game_info,
                            verbose = args.verbose,
                            pretend_run = args.pretend_run,
                            exit_on_failure = args.exit_on_failure)
                        if not success:
                            system.LogError(
                                message = "Packing of save failed!",
                                game_supercategory = game_supercategory,
                                game_category = game_category,
                                game_subcategory = game_subcategory,
                                game_name = game_name,
                                quit_program = True)

    # Unpack saves
    elif args.action == config.SaveActionType.UNPACK:
        for game_supercategory in parser.get_selected_supercategories():
            for game_category, game_subcategories in parser.get_selected_subcategories().items():
                for game_subcategory in game_subcategories:
                    game_names = gameinfo.FindJsonGameNames(
                        game_supercategory,
                        game_category,
                        game_subcategory)
                    for game_name in game_names:
                        game_info = gameinfo.GameInfo(
                            game_supercategory = game_supercategory,
                            game_category = game_category,
                            game_subcategory = game_subcategory,
                            game_name = game_name,
                            verbose = verbose,
                            pretend_run = pretend_run,
                            exit_on_failure = exit_on_failure)
                        success = collection.UnpackSave(
                            game_info = game_info,
                            verbose = args.verbose,
                            pretend_run = args.pretend_run,
                            exit_on_failure = args.exit_on_failure)
                        if not success:
                            system.LogError(
                                message = "Unpacking of save failed!",
                                game_supercategory = game_supercategory,
                                game_category = game_category,
                                game_subcategory = game_subcategory,
                                game_name = game_name,
                                quit_program = True)

    # Import save paths
    elif args.action == config.SaveActionType.IMPORT_SAVE_PATHS:
        for game_supercategory in parser.get_selected_supercategories():
            for game_category, game_subcategories in parser.get_selected_subcategories().items():
                for game_subcategory in game_subcategories:
                    game_names = gameinfo.FindJsonGameNames(
                        game_supercategory,
                        game_category,
                        game_subcategory)
                    for game_name in game_names:
                        game_info = gameinfo.GameInfo(
                            game_supercategory = game_supercategory,
                            game_category = game_category,
                            game_subcategory = game_subcategory,
                            game_name = game_name,
                            verbose = verbose,
                            pretend_run = pretend_run,
                            exit_on_failure = exit_on_failure)
                        success = collection.ImportGameSavePaths(
                            game_info = game_info,
                            verbose = args.verbose,
                            pretend_run = args.pretend_run,
                            exit_on_failure = args.exit_on_failure)
                        if not success:
                            system.LogError(
                                message = "Import of save paths failed!",
                                game_supercategory = game_supercategory,
                                game_category = game_category,
                                game_subcategory = game_subcategory,
                                game_name = game_name,
                                quit_program = True)

# Start
if __name__ == "__main__":
    system.RunMain(main)
