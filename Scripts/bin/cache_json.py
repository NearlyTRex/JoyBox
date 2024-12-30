#!/usr/bin/env python3

# Imports
import os, os.path
import sys

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.append(lib_folder)
import config
import system
import gameinfo
import cache
import arguments
import setup

# Parse arguments
parser = arguments.ArgumentParser(description = "Cache game files.")
parser.add_input_path_argument()
parser.add_enum_argument(
    args = ("-l", "--source_type"),
    arg_type = config.SourceType,
    default = config.SourceType.REMOTE,
    description = "Source type")
parser.add_game_category_argument()
parser.add_game_subcategory_argument()
parser.add_game_name_argument()
parser.add_boolean_argument(args = ("-k", "--keep_setup_files"), description = "Keep setup files")
parser.add_boolean_argument(args = ("--force_cache_refresh"), description = "Force refresh of cached files")
parser.add_common_arguments()
args, unknown = parser.parse_known_args()

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Get input path
    input_path = parser.get_input_path()

    # Json file to load
    json_file = None

    # Prefer input file if it was specified
    if args.input_path:
        json_file = parser.get_input_path()

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
    if not system.IsPathFile(json_file):
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
