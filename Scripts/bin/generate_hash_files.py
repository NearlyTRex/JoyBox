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
import environment
import hashing
import ini
import setup

# Parse arguments
parser = argparse.ArgumentParser(description="Generate file hashes.")
parser.add_argument("-i", "--input_path", type=str, help="Input path")
parser.add_argument("-u", "--file_supercategory",
    choices=config.game_supercategories,
    default=config.game_supercategory_roms,
    help="File supercategory"
)
parser.add_argument("-c", "--file_category", type=str, help="File category")
parser.add_argument("-s", "--file_subcategory", type=str, help="File subcategory")
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
args, unknown = parser.parse_known_args()

# Check input path
input_path = ""
if args.input_path:
    input_path = os.path.realpath(args.input_path)
    if not os.path.exists(input_path):
        system.LogError("Path '%s' does not exist" % args.input_path)
        sys.exit(-1)

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Get flags
    verbose = ini.GetIniBoolValue("UserData.Flags", "verbose")
    exit_on_failure = ini.GetIniBoolValue("UserData.Flags", "exit_on_failure")

    # Get source file root
    source_file_root = ""
    if args.source_files == "input":
        source_file_root = input_path
    elif args.source_files == "stored":
        source_file_root = environment.GetSupercategoryRootDir(args.file_supercategory)

    # Manually specify all parameters
    if args.generation_mode == "custom":
        if not args.file_category:
            system.LogError("File category is required for custom mode")
            sys.exit(-1)
        if not args.file_subcategory:
            system.LogError("File subcategory is required for custom mode")
            sys.exit(-1)
        hashing.HashCategoryFiles(
            input_path = source_file_root,
            file_supercategory = args.file_supercategory,
            file_category = args.file_category,
            file_subcategory = args.file_subcategory,
            verbose = verbose,
            exit_on_failure = exit_on_failure)

    # Automatic according to standard layout
    elif args.generation_mode == "standard":

        # Specific category/subcategory
        if args.file_category and args.file_subcategory:
            hashing.HashCategoryFiles(
                input_path = os.path.join(source_file_root, args.file_category, args.file_subcategory),
                file_supercategory = args.file_supercategory,
                file_category = args.file_category,
                file_subcategory = args.file_subcategory,
                verbose = verbose,
                exit_on_failure = exit_on_failure)

        # Specific category/all subcategories in that category
        elif args.file_category:
            for file_subcategory in config.game_subcategories[args.file_category]:
                hashing.HashCategoryFiles(
                    input_path = os.path.join(source_file_root, args.file_category, file_subcategory),
                    file_supercategory = args.file_supercategory,
                    file_category = args.file_category,
                    file_subcategory = file_subcategory,
                    verbose = verbose,
                    exit_on_failure = exit_on_failure)

        # All categories/subcategories
        else:
            for file_category in config.game_categories:
                for file_subcategory in config.game_subcategories[file_category]:
                    hashing.HashCategoryFiles(
                        input_path = os.path.join(source_file_root, file_category, file_subcategory),
                        file_supercategory = args.file_supercategory,
                        file_category = file_category,
                        file_subcategory = file_subcategory,
                        verbose = verbose,
                        exit_on_failure = exit_on_failure)

# Start
main()
