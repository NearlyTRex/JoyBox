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
import metadata
import setup

# Parse arguments
parser = argparse.ArgumentParser(description="Build metadata file.")
parser.add_argument("rom_path", help="Rom path")
parser.add_argument("-c", "--rom_category", required=True, type=str, help="Rom category")
parser.add_argument("-s", "--rom_subcategory", required=True, type=str, help="Rom subcategory")
parser.add_argument("-o", "--output_file", type=str, default="metadata.txt", help="Output metadata file")
args, unknown = parser.parse_known_args()

# Check rom path
rom_root_path = os.path.realpath(args.rom_path)
if not os.path.exists(rom_root_path):
    system.LogError("Could not find rom root path '%s'" % rom_root_path)
    sys.exit(1)

# Paths
output_file = os.path.realpath(args.output_file)

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Build metadata file
    metadata_obj = metadata.Metadata()
    if os.path.isfile(output_file):
        metadata_obj.import_from_metadata_file(output_file)
    metadata_obj.scan_roms(
        rom_path = rom_root_path,
        rom_category = args.rom_category,
        rom_subcategory = args.rom_subcategory)
    metadata_obj.export_to_metadata_file(output_file)

# Start
main()
