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
parser.add_argument("game_path", help="Game path")
parser.add_argument("-c", "--game_category", required=True, type=str, help="Game category")
parser.add_argument("-s", "--game_subcategory", required=True, type=str, help="Game subcategory")
parser.add_argument("-o", "--output_file", type=str, default="metadata.txt", help="Output metadata file")
parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose mode")
parser.add_argument("-p", "--pretend_run", action="store_true", help="Do a pretend run with no permanent changes")
parser.add_argument("-x", "--exit_on_failure", action="store_true", help="Enable exit on failure mode")
args, unknown = parser.parse_known_args()

# Check game path
game_root_path = os.path.realpath(args.game_path)
if not os.path.exists(game_root_path):
    system.LogErrorAndQuit("Could not find game root path '%s'" % game_root_path)

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
    metadata_obj.scan_games(
        game_path = game_root_path,
        game_category = args.game_category,
        game_subcategory = args.game_subcategory)
    metadata_obj.export_to_metadata_file(output_file)

# Start
main()
