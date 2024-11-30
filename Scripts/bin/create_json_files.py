#!/usr/bin/env python3

# Imports
import os, os.path
import sys
import argparse

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.append(lib_folder)
import config
import environment
import system
import collection
import setup
import ini

# Parse arguments
parser = argparse.ArgumentParser(description="Create or update json files.")
parser.add_argument("-i", "--input_path", type=str, help="Input path")
parser.add_argument("-u", "--game_supercategory",
    choices=config.game_supercategories,
    default=config.game_supercategory_roms,
    help="Game supercategory"
)
parser.add_argument("-c", "--game_category", type=str, help="Game category")
parser.add_argument("-s", "--game_subcategory", type=str, help="Game subcategory")
parser.add_argument("-n", "--game_title", type=str, help="Game title")
parser.add_argument("-e", "--source_type",
    choices=config.source_types,
    default=config.source_type_remote,
    help="Source types"
)
parser.add_argument("-f", "--source_files",
    choices=[
        "input",
        "stored"
    ],
    default="stored", help="Source files"
)
parser.add_argument("-m", "--generation_mode",
    choices=[
        "custom",
        "standard"
    ],
    default="standard", help="Generation mode"
)
parser.add_argument("-t", "--passphrase_type",
    choices=config.passphrase_types,
    default=config.passphrase_type_none, help="Passphrase type"
)
parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose mode")
parser.add_argument("-p", "--pretend_run", action="store_true", help="Do a pretend run with no permanent changes")
parser.add_argument("-x", "--exit_on_failure", action="store_true", help="Enable exit on failure mode")
args, unknown = parser.parse_known_args()

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Get input path
    input_path = ""
    if args.input_path:
        input_path = os.path.realpath(args.input_path)
        if not os.path.exists(input_path):
            system.LogErrorAndQuit("Path '%s' does not exist" % args.input_path)

    # Get source file root
    source_file_root = ""
    if args.source_files == "input":
        source_file_root = input_path
    elif args.source_files == "stored":
        source_file_root = environment.GetLockerGamingSupercategoryRootDir(args.game_supercategory, args.source_type)

    # Get passphrase
    passphrase = None
    if args.passphrase_type == config.passphrase_type_general:
        passphrase = ini.GetIniValue("UserData.Protection", "general_passphrase")
    elif args.passphrase_type == config.passphrase_type_locker:
        passphrase = ini.GetIniValue("UserData.Protection", "locker_passphrase")

    # Manually specify all parameters
    if args.generation_mode == "custom":
        if not args.game_category:
            system.LogErrorAndQuit("File category is required for custom mode")
        if not args.game_subcategory:
            system.LogErrorAndQuit("File subcategory is required for custom mode")
        if not args.game_title:
            system.LogErrorAndQuit("File title is required for custom mode")
        collection.CreateGameJsonFile(
            game_category = args.game_category,
            game_subcategory = args.game_subcategory,
            game_title = args.game_title,
            game_root = source_file_root,
            passphrase = passphrase,
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure)

    # Automatic according to standard layout
    elif args.generation_mode == "standard":

        # Specific category/subcategory
        if args.game_category and args.game_subcategory:
            collection.CreateGameJsonFiles(
                game_category = args.game_category,
                game_subcategory = args.game_subcategory,
                game_root = source_file_root,
                passphrase = passphrase,
                verbose = args.verbose,
                pretend_run = args.pretend_run,
                exit_on_failure = args.exit_on_failure)

        # Specific category/all subcategories in that category
        elif args.game_category:
            for gaming_subcategory in config.game_subcategories[args.game_category]:
                collection.CreateGameJsonFiles(
                    game_category = args.game_category,
                    game_subcategory = gaming_subcategory,
                    game_root = source_file_root,
                    passphrase = passphrase,
                    verbose = args.verbose,
                    pretend_run = args.pretend_run,
                    exit_on_failure = args.exit_on_failure)

        # All categories/subcategories
        else:
            for gaming_category in config.game_categories:
                for gaming_subcategory in config.game_subcategories[gaming_category]:
                    collection.CreateGameJsonFiles(
                        game_category = gaming_category,
                        game_subcategory = gaming_subcategory,
                        game_root = source_file_root,
                        passphrase = passphrase,
                        verbose = args.verbose,
                        pretend_run = args.pretend_run,
                        exit_on_failure = args.exit_on_failure)

# Start
main()
