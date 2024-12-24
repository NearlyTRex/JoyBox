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
import gameinfo
import cache
import setup

# Parse arguments
parser = argparse.ArgumentParser(description="Cache game files.")
parser.add_argument("-i", "--input_file", type=str, help="Json file to cache")
parser.add_argument("-e", "--source_type",
    choices=config.SourceType.members(),
    default=config.SourceType.REMOTE,
    help="Source types"
)
parser.add_argument("-c", "--game_category", type=str, help="Game category")
parser.add_argument("-s", "--game_subcategory", type=str, help="Game subcategory")
parser.add_argument("-n", "--game_name", type=str, help="Game name")
parser.add_argument("-k", "--keep_setup_files", action="store_true", help="Keep setup files")
parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose mode")
parser.add_argument("-p", "--pretend_run", action="store_true", help="Do a pretend run with no permanent changes")
parser.add_argument("-x", "--exit_on_failure", action="store_true", help="Enable exit on failure mode")
parser.add_argument("--force_cache_refresh", action="store_true", help="Force refresh of cached files")
args, unknown = parser.parse_known_args()
if not args.path:
    parser.print_help()
    system.QuitProgram()

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Json file to load
    json_file = None

    # Prefer input file if it was specified
    if args.input_file:
        if os.path.isfile(args.input_file):
            json_file = args.input_file
        else:
            json_file = os.path.join(environment.GetJsonRomsMetadataRootDir(), json_file)

    # Next use category values
    elif args.game_category and args.game_subcategory and args.game_name:
        json_file = environment.GetJsonRomMetadataFile(
            game_category = args.game_category,
            game_subcategory = args.game_subcategory,
            game_name = args.game_name)

    # Check json file
    if not json_file:
        gui.DisplayErrorPopup(
            title_text = "No json file specified",
            message_text = "No json file was specified")
    if not os.path.isfile(json_file):
        gui.DisplayErrorPopup(
            title_text = "Json file not found",
            message_text = "Json file %s was not found" % json_file)

    # Get game info
    game_info = gameinfo.GameInfo(
        json_file = json_file,
        verbose = args.verbose,
        pretend_run = args.pretend_run,
        exit_on_failure = args.exit_on_failure)

    # Force cache refresh
    if args.force_cache_refresh:
        cache.RemoveGameFromCache(
            game_info = game_info,
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure)

    # Install game to cache
    cache.InstallGameToCache(
        game_info = game_info,
        source_type = args.source_type,
        keep_setup_files = args.keep_setup_files,
        verbose = args.verbose,
        pretend_run = args.pretend_run,
        exit_on_failure = args.exit_on_failure)

# Start
main()
