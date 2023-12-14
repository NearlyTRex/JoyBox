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
import webpage
import metadata
import setup

# Parse arguments
parser = argparse.ArgumentParser(description="Download missing metadata.")
parser.add_argument("metadata_dir", help="Metadata dir")
parser.add_argument("-f", "--metadata_format",
    choices=[
        config.metadata_format_gamelist,
        config.metadata_format_pegasus
    ],
    default=config.metadata_format_pegasus
)
parser.add_argument("-p", "--metadata_platform",
    choices=[
        config.metadata_source_thegamesdb,
        config.metadata_source_gamefaqs,
        config.metadata_source_itchio
    ],
    default=config.metadata_source_gamefaqs
)
parser.add_argument("--only_check_description", action="store_true", help="Only check descriptions")
parser.add_argument("--only_check_genre", action="store_true", help="Only check genres")
parser.add_argument("--only_check_developer", action="store_true", help="Only check developers")
parser.add_argument("--only_check_publisher", action="store_true", help="Only check publishers")
parser.add_argument("--only_check_release", action="store_true", help="Only check releases")
parser.add_argument("--force_download", action="store_true", help="Force download")
parser.add_argument("-a", "--select_automatically", action="store_true", help="Select game automatically")
parser.add_argument("-i", "--ignore_unowned", action="store_true", help="Ignore unowned games")
args, unknown = parser.parse_known_args()

# Check pegasus dir
if not os.path.exists(args.metadata_dir):
    print("Could not find pegasus path '%s'" % args.metadata_dir)
    sys.exit(1)

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Create web driver
    web_driver = webpage.CreateWebDriver()

    # Find missing metadata
    metadata_dir = os.path.realpath(args.metadata_dir)
    for file in system.BuildFileList(metadata_dir):
        if metadata.IsMetadataFile(file, args.metadata_format):
            metadata_obj = metadata.Metadata()
            metadata_obj.import_from_metadata_file(file, args.metadata_format)

            # Check for missing metadata keys
            metadata_keys_to_check = []
            is_missing_metadata = False
            if args.force_download:
                is_missing_metadata = True
            else:
                if args.only_check_description:
                    metadata_keys_to_check = [metadata_key_description]
                elif args.only_check_genre:
                    metadata_keys_to_check = [config.metadata_key_genre]
                elif args.only_check_developer:
                    metadata_keys_to_check = [config.metadata_key_developer]
                elif args.only_check_publisher:
                    metadata_keys_to_check = [config.metadata_key_publisher]
                elif args.only_check_release:
                    metadata_keys_to_check = [config.metadata_key_release]
                else:
                    metadata_keys_to_check = metadata.GetMissingMetadataKeys()
                is_missing_metadata = metadata_obj.is_missing_data(metadata_keys_to_check)
            if not is_missing_metadata:
                continue

            # Iterate through each game entry to fill in any missing data
            for game_platform in metadata_obj.get_sorted_platforms():
                for game_name in metadata_obj.get_sorted_names(game_platform):
                    if not args.force_download:
                        if not metadata_obj.is_entry_missing_data(game_platform, game_name, metadata_keys_to_check):
                            continue

                    # Get entry
                    game_entry = metadata_obj.get_game(game_platform, game_name)

                    # Collect metadata
                    metadata_result = None
                    if args.metadata_platform == config.metadata_source_thegamesdb:
                        metadata_result = metadata.CollectMetadataFromTGDB(
                            web_driver = web_driver,
                            game_platform = game_platform,
                            game_name = game_name,
                            select_automatically = args.select_automatically,
                            ignore_unowned = args.ignore_unowned)
                    elif args.metadata_platform == config.metadata_source_gamefaqs:
                        metadata_result = metadata.CollectMetadataFromGameFAQS(
                            web_driver = web_driver,
                            game_platform = game_platform,
                            game_name = game_name,
                            select_automatically = args.select_automatically,
                            ignore_unowned = args.ignore_unowned)
                    elif args.metadata_platform == config.metadata_source_itchio:
                        metadata_result = metadata.CollectMetadataFromItchio(
                            web_driver = web_driver,
                            game_platform = game_platform,
                            game_name = game_name,
                            select_automatically = args.select_automatically,
                            ignore_unowned = args.ignore_unowned)

                    # Set metadata that was not already present in the file
                    if metadata_result:
                        for metadata_key in metadata.GetReplaceableMetadataKeys():

                            # Ignore keys not in result
                            if not metadata_key in metadata_result.keys():
                                continue

                            # Check if we should set the new data
                            should_set_data = False
                            if metadata_key == config.metadata_key_players:
                                should_set_data = True
                            if metadata_key == config.metadata_key_coop:
                                should_set_data = True
                            elif not metadata_key in game_entry.keys():
                                should_set_data = True

                            # Set new data
                            if should_set_data:
                                game_entry[metadata_key] = metadata_result[metadata_key]

                    # Write metadata back to file
                    metadata_obj.set_game(game_platform, game_name, game_entry)
                    metadata_obj.export_to_metadata_file(file, args.metadata_format)

    # Cleanup web driver
    webpage.DestroyWebDriver(web_driver)

# Start
main()
