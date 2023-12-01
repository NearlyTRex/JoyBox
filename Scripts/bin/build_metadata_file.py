#!/usr/bin/env python3

# Imports
import os
import os.path
import sys
import argparse

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.append(lib_folder)
import config
import command
import environment
import metadata
import system
import setup

# Parse arguments
parser = argparse.ArgumentParser(description="Build metadata file.")
parser.add_argument("rom_path", help="Rom path")
parser.add_argument("-f", "--metadata_format",
    choices=[
        config.metadata_format_gamelist,
        config.metadata_format_pegasus
    ],
    default=config.metadata_format_pegasus
)
parser.add_argument("-c", "--rom_category", required=True, type=str, help="Rom category")
parser.add_argument("-s", "--rom_subcategory", required=True, type=str, help="Rom subcategory")
parser.add_argument("-o", "--output_file", type=str, default="gamelist.txt", help="Output gamelist file")
parser.add_argument("-j", "--json_files_only", action="store_true", help="Use only json files in the search")
args, unknown = parser.parse_known_args()

# Check rom path
rom_root_path = os.path.realpath(args.rom_path)
if not os.path.exists(rom_root_path):
    print("Could not find rom root path '%s'" % rom_root_path)
    sys.exit(1)

# Paths
output_file = os.path.realpath(args.output_file)

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Build metadata file
    metadata_obj = metadata.Metadata()
    metadata_obj.scan_roms(
        rom_path = rom_root_path,
        rom_category = args.rom_category,
        rom_subcategory = args.rom_subcategory,
        use_json_file = args.json_files_only)
    metadata_obj.export_to_metadata_file(output_file, args.metadata_format)

# Start
environment.RunAsRootIfNecessary(main)
