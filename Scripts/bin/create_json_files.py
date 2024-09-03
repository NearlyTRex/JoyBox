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
parser.add_argument("-u", "--file_supercategory",
    choices=config.game_supercategories,
    default=config.game_supercategory_roms,
    help="File supercategory"
)
parser.add_argument("-c", "--file_category", type=str, help="File category")
parser.add_argument("-s", "--file_subcategory", type=str, help="File subcategory")
parser.add_argument("-n", "--file_title", type=str, help="File title")
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
        source_file_root = environment.GetLockerGamingSupercategoryRootDir(args.file_supercategory, args.source_type)

    # Get passphrase
    passphrase = None
    if args.passphrase_type == config.passphrase_type_general:
        passphrase = ini.GetIniValue("UserData.Protection", "general_passphrase")
    elif args.passphrase_type == config.passphrase_type_locker:
        passphrase = ini.GetIniValue("UserData.Protection", "locker_passphrase")

    # Manually specify all parameters
    if args.generation_mode == "custom":
        if not args.file_category:
            system.LogErrorAndQuit("File category is required for custom mode")
        if not args.file_subcategory:
            system.LogErrorAndQuit("File subcategory is required for custom mode")
        if not args.file_title:
            system.LogErrorAndQuit("File title is required for custom mode")
        collection.CreateGameJsonFile(
            file_category = args.file_category,
            file_subcategory = args.file_subcategory,
            file_title = args.file_title,
            file_root = source_file_root,
            passphrase = passphrase,
            verbose = args.verbose,
            exit_on_failure = args.exit_on_failure)

    # Automatic according to standard layout
    elif args.generation_mode == "standard":

        # Specific category/subcategory
        if args.file_category and args.file_subcategory:
            collection.CreateGameJsonFiles(
                file_category = args.file_category,
                file_subcategory = args.file_subcategory,
                file_root = source_file_root,
                passphrase = passphrase,
                verbose = args.verbose,
                exit_on_failure = args.exit_on_failure)

        # Specific category/all subcategories in that category
        elif args.file_category:
            for file_subcategory in config.game_subcategories[args.file_category]:
                collection.CreateGameJsonFiles(
                    file_category = args.file_category,
                    file_subcategory = file_subcategory,
                    file_root = source_file_root,
                    passphrase = passphrase,
                    verbose = args.verbose,
                    exit_on_failure = args.exit_on_failure)

        # All categories/subcategories
        else:
            for file_category in config.game_categories:
                for file_subcategory in config.game_subcategories[file_category]:
                    collection.CreateGameJsonFiles(
                        file_category = file_category,
                        file_subcategory = file_subcategory,
                        file_root = source_file_root,
                        passphrase = passphrase,
                        verbose = args.verbose,
                        exit_on_failure = args.exit_on_failure)

# Start
main()
