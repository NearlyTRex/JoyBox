#!/usr/bin/env python3

# Imports
import os, os.path
import sys

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.append(lib_folder)
import config
import environment
import metadata
import system
import arguments
import setup
import logger
import paths
import prompts
import reports

# Parse arguments
parser = arguments.ArgumentParser(description = "Find games with missing metadata fields.")
parser.add_enum_argument(
    args = ("-k", "--keys"),
    arg_type = config.MetadataKeyType,
    default = config.MetadataKeyType.DOWNLOADABLE,
    description = "Which metadata keys to check")
parser.add_common_arguments()
args, unknown = parser.parse_known_args()

# Main
def main():

    # Check requirements
    setup.check_requirements()

    # Setup logging
    logger.setup_logging()

    # Get metadata dir
    metadata_dir = environment.get_game_pegasus_metadata_root_dir()

    # Determine keys to check
    keys_to_check = []
    if args.keys == config.MetadataKeyType.MINIMUM:
        keys_to_check = config.metadata_keys_minimum
    elif args.keys == config.MetadataKeyType.DOWNLOADABLE:
        keys_to_check = config.metadata_keys_downloadable
    elif args.keys == config.MetadataKeyType.ALL:
        keys_to_check = config.metadata_keys_all

    # Show preview
    if not args.no_preview:
        details = [
            "Metadata dir: %s" % metadata_dir,
            "Keys to check: %s" % ", ".join(keys_to_check)
        ]
        if not prompts.prompt_for_preview("Find missing game metadata", details):
            logger.log_warning("Operation cancelled by user")
            return

    # Track missing metadata by key
    missing_by_key = {key: [] for key in keys_to_check}
    total_entries = 0
    entries_with_missing = set()

    # Scan metadata files
    for filename in paths.build_file_list(metadata_dir):
        if not environment.is_game_metadata_file(filename):
            continue

        # Load metadata
        metadata_obj = metadata.Metadata()
        metadata_obj.import_from_metadata_file(filename)
        for game_platform in metadata_obj.get_sorted_platforms():
            for game_entry in metadata_obj.get_sorted_entries(game_platform):
                total_entries += 1
                game_name = game_entry.get_game()
                entry_id = "%s - %s" % (game_platform, game_name)

                # Check each key
                for key in keys_to_check:
                    if not game_entry.is_key_set(key) or game_entry.get_value(key) == "":
                        missing_by_key[key].append(entry_id)
                        entries_with_missing.add(entry_id)

    # Report results
    logger.log_header("Scan complete: %d total entries, %d with missing metadata" % (total_entries, len(entries_with_missing)))

    # Write results per key
    for key in keys_to_check:
        missing_items = sorted(missing_by_key[key])
        if len(missing_items) > 0:
            reports.write_list_report(
                items = missing_items,
                title = "\nMissing '%s':" % key,
                max_display = 10 if args.verbose else 0,
                report_file = "Missing_%s.txt" % key,
                verbose = args.verbose,
                pretend_run = args.pretend_run)

# Start
if __name__ == "__main__":
    system.run_main(main)
