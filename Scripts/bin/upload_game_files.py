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
import collection
import gameinfo
import arguments
import setup

# Parse arguments
parser = arguments.ArgumentParser(description = "Upload game files.")
parser.add_input_path_argument()
parser.add_game_supercategory_argument()
parser.add_game_category_argument()
parser.add_game_subcategory_argument()
parser.add_game_name_argument()
parser.add_enum_argument(
    args = ("-l", "--source_type"),
    arg_type = config.SourceType,
    default = config.SourceType.LOCAL,
    description = "Source type")
parser.add_enum_argument(
    args = ("-m", "--generation_mode"),
    arg_type = config.GenerationModeType,
    default = config.GenerationModeType.STANDARD,
    description = "Generation mode")
parser.add_enum_argument(
    args = ("-t", "--locker_type"),
    arg_type = config.LockerType,
    description = "Locker type")
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
        if not args.game_name:
            system.LogError("Game name is required for custom mode", quit_program = True)
        game_info = gameinfo.GameInfo(
            game_supercategory = args.game_supercategory,
            game_category = args.game_category,
            game_subcategory = args.game_subcategory,
            game_name = args.game_name,
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure)
        success = collection.UploadGameFiles(
            game_info = game_info,
            game_root = parser.get_input_path(),
            locker_type = args.locker_type,
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure)
        if not success:
            system.LogError(
                message = "Upload of game files failed!",
                game_supercategory = args.game_supercategory,
                game_category = args.game_category,
                game_subcategory = args.game_subcategory,
                game_name = args.game_name,
                quit_program = True)

    # Automatic according to standard layout
    elif args.generation_mode == config.GenerationModeType.STANDARD:
        for game_supercategory in parser.get_selected_supercategories():
            for game_category, game_subcategories in parser.get_selected_subcategories().items():
                for game_subcategory in game_subcategories:
                    game_names = gameinfo.FindLockerGameNames(
                        game_supercategory,
                        game_category,
                        game_subcategory,
                        args.source_type)
                    for game_name in game_names:
                        game_root = environment.GetLockerGamingFilesDir(
                            game_supercategory,
                            game_category,
                            game_subcategory,
                            game_name,
                            args.source_type)
                        game_info = gameinfo.GameInfo(
                            game_supercategory = game_supercategory,
                            game_category = game_category,
                            game_subcategory = game_subcategory,
                            game_name = game_name,
                            verbose = args.verbose,
                            pretend_run = args.pretend_run,
                            exit_on_failure = args.exit_on_failure)
                        success = collection.UploadGameFiles(
                            game_info = game_info,
                            game_root = game_root,
                            locker_type = args.locker_type,
                            verbose = args.verbose,
                            pretend_run = args.pretend_run,
                            exit_on_failure = args.exit_on_failure)
                        if not success:
                            system.LogError(
                                message = "Upload of game files failed!",
                                game_supercategory = game_supercategory,
                                game_category = game_category,
                                game_subcategory = game_subcategory,
                                game_name = game_name,
                                quit_program = True)

# Start
if __name__ == "__main__":
    system.RunMain(main)
