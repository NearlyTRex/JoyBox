#!/usr/bin/env python3

# Imports
import os, os.path
import sys

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.append(lib_folder)
import config
import system
import collection
import arguments
import setup

# Parse arguments
parser = arguments.ArgumentParser(description = "Build metadata files.")
parser.add_input_path_argument()
parser.add_game_category_arguments()
parser.add_game_name_argument()
parser.add_source_type_argument()
parser.add_generation_mode_argument()
parser.add_common_arguments()
args, unknown = parser.parse_known_args()

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Get source file root
    source_file_root = None
    if args.input_path:
        source_file_root = parser.get_input_path()
    else:
        source_file_root = environment.GetLockerGamingSupercategoryRootDir(args.game_supercategory, args.source_type.value)

    # Manually specify all parameters
    if args.generation_mode == config.GenerationModeType.CUSTOM:
        if not args.game_category:
            system.LogErrorAndQuit("Game category is required for custom mode")
        if not args.game_subcategory:
            system.LogErrorAndQuit("Game subcategory is required for custom mode")
        if not args.game_name:
            system.LogErrorAndQuit("Game name is required for custom mode")
        collection.AddMetadataEntry(
            game_category = args.game_category,
            game_subcategory = args.game_subcategory,
            game_name = args.game_name,
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure)

    # Automatic according to standard layout
    elif args.generation_mode == config.GenerationModeType.STANDARD:

        # Specific category/subcategory
        if args.game_category and args.game_subcategory:
            collection.AddMetadataEntries(
                game_category = args.game_category,
                game_subcategory = args.game_subcategory,
                game_root = source_file_root,
                verbose = args.verbose,
                pretend_run = args.pretend_run,
                exit_on_failure = args.exit_on_failure)

        # Specific category/all subcategories in that category
        elif args.game_category:
            for gaming_subcategory in config.subcategory_map[args.game_category]:
                collection.AddMetadataEntries(
                    game_category = args.game_category,
                    game_subcategory = gaming_subcategory,
                    game_root = source_file_root,
                    verbose = args.verbose,
                    pretend_run = args.pretend_run,
                    exit_on_failure = args.exit_on_failure)

        # All categories/subcategories
        else:
            for gaming_category in config.Category.members():
                for gaming_subcategory in config.subcategory_map[gaming_category]:
                    collection.AddMetadataEntries(
                        game_category = gaming_category,
                        game_subcategory = gaming_subcategory,
                        game_root = source_file_root,
                        verbose = args.verbose,
                        pretend_run = args.pretend_run,
                        exit_on_failure = args.exit_on_failure)

# Start
main()
