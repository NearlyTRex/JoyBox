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
import hashing
import ini
import arguments
import setup

# Parse arguments
parser = arguments.ArgumentParser(description = "Generate file hashes.")
parser.add_input_path_argument()
parser.add_game_category_arguments()
parser.add_source_type_argument()
parser.add_generation_mode_argument()
parser.add_passphrase_type_argument()
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
        source_file_root = environment.GetLockerGamingSupercategoryRootDir(args.game_supercategory, args.source_type)

    # Get passphrase
    passphrase = None
    if args.passphrase_type == config.PassphraseType.GENERAL:
        passphrase = ini.GetIniValue("UserData.Protection", "general_passphrase")
    elif args.passphrase_type == config.PassphraseType.LOCKER:
        passphrase = ini.GetIniValue("UserData.Protection", "locker_passphrase")

    # Manually specify all parameters
    if args.generation_mode == config.GenerationModeType.CUSTOM:
        if not args.game_category:
            system.LogErrorAndQuit("Game category is required for custom mode")
        if not args.game_subcategory:
            system.LogErrorAndQuit("Game subcategory is required for custom mode")
        hashing.HashCategoryFiles(
            input_path = source_file_root,
            game_supercategory = args.game_supercategory,
            game_category = args.game_category,
            game_subcategory = args.game_subcategory,
            passphrase = passphrase,
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure)

    # Automatic according to standard layout
    elif args.generation_mode == config.GenerationModeType.STANDARD:

        # Specific category/subcategory
        if args.game_category and args.game_subcategory:
            hashing.HashCategoryFiles(
                input_path = os.path.join(source_file_root, args.game_category, args.game_subcategory),
                game_supercategory = args.game_supercategory,
                game_category = args.game_category,
                game_subcategory = args.game_subcategory,
                passphrase = passphrase,
                verbose = args.verbose,
                pretend_run = args.pretend_run,
                exit_on_failure = args.exit_on_failure)

        # Specific category/all subcategories in that category
        elif args.game_category:
            for game_subcategory in config.subcategory_map[args.game_category]:
                hashing.HashCategoryFiles(
                    input_path = os.path.join(source_file_root, args.game_category, game_subcategory),
                    game_supercategory = args.game_supercategory,
                    game_category = args.game_category,
                    game_subcategory = game_subcategory,
                    passphrase = passphrase,
                    verbose = args.verbose,
                    pretend_run = args.pretend_run,
                    exit_on_failure = args.exit_on_failure)

        # All categories/subcategories
        else:
            for game_category in config.Category.members():
                for game_subcategory in config.subcategory_map[game_category]:
                    hashing.HashCategoryFiles(
                        input_path = os.path.join(source_file_root, game_category, game_subcategory),
                        game_supercategory = args.game_supercategory,
                        game_category = game_category,
                        game_subcategory = game_subcategory,
                        passphrase = passphrase,
                        verbose = args.verbose,
                        pretend_run = args.pretend_run,
                        exit_on_failure = args.exit_on_failure)

# Start
main()
