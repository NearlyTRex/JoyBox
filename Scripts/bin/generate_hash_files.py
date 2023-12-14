#!/usr/bin/env python3

# Imports
import os, os.path
import sys
import argparse

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.append(lib_folder)
import environment
import metadata
import hashing
import setup

# Parse arguments
parser = argparse.ArgumentParser(description="Generate file hashes.")
parser.add_argument("-i", "--input_path", type=str, help="Input path")
parser.add_argument("-d", "--disc_name", type=str, help="Disc name")
parser.add_argument("-u", "--file_supercategory",
    choices=metadata.GetMetadataSupercategories(),
    default=metadata.GetMetadataDefaultSupercategory(),
    help="File supercategory"
)
parser.add_argument("-c", "--file_category", type=str, help="File category")
parser.add_argument("-s", "--file_subcategory", type=str, help="File subcategory")
parser.add_argument("-a", "--all_files", action="store_true", help="All files")
parser.add_argument("-f", "--source_files",
    choices=[
        "input",
        "stored"
    ],
    default="input", help="Source files"
)
parser.add_argument("-m", "--generation_mode",
    choices=[
        "custom",
        "standard"
    ],
    default="custom", help="Generation mode"
)
args, unknown = parser.parse_known_args()

# Check input path
input_path = ""
if args.input_path:
    input_path = os.path.realpath(args.input_path)
    if not os.path.exists(input_path):
        print("Path '%s' does not exist" % args.input_path)
        sys.exit(-1)

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Get source file root
    source_file_root = ""
    if args.source_files == "input":
        source_file_root = input_path
    elif args.source_files == "stored":
        source_file_root = environment.GetSupercategoryRootDir(args.file_supercategory)

    # Manually specify all parameters
    if args.generation_mode == "custom":
        if not args.file_category:
            print("File category is required for custom mode")
            sys.exit(-1)
        if not args.file_subcategory:
            print("File subcategory is required for custom mode")
            sys.exit(-1)
        hashing.HashCustomFiles(
            input_path = source_file_root,
            disc_name = args.disc_name,
            file_supercategory = args.file_supercategory,
            file_category = args.file_category,
            file_subcategory = args.file_subcategory,
            all_files = args.all_files)

    # Automatic according to standard layout
    elif args.generation_mode == "standard":

        # Specific category/subcategory
        if args.file_category and args.file_subcategory:
            hashing.HashStandardFiles(
                input_path = os.path.join(source_file_root, args.file_category, args.file_subcategory),
                file_supercategory = args.file_supercategory,
                file_category = args.file_category,
                file_subcategory = args.file_subcategory,
                all_files = args.all_files)

        # Specific category/all subcategories in that category
        elif args.file_category:
            for file_subcategory in metadata.GetMetadataSubcategories(args.file_category):
                hashing.HashStandardFiles(
                    input_path = os.path.join(source_file_root, args.file_category, file_subcategory),
                    file_supercategory = args.file_supercategory,
                    file_category = args.file_category,
                    file_subcategory = file_subcategory,
                    all_files = args.all_files)

        # All categories/subcategories
        else:
            for file_category in metadata.GetMetadataCategories():
                for file_subcategory in metadata.GetMetadataSubcategories(file_category):
                    hashing.HashStandardFiles(
                        input_path = os.path.join(source_file_root, file_category, file_subcategory),
                        file_supercategory = args.file_supercategory,
                        file_category = file_category,
                        file_subcategory = file_subcategory,
                        all_files = args.all_files)

# Start
main()
