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
import gameinfo
import system
import arguments
import setup
import logger
import paths
import prompts
import reports

# Parse arguments
parser = arguments.ArgumentParser(description = "Find missing game assets.")
parser.add_common_arguments()
args, unknown = parser.parse_known_args()

# Main
def main():

    # Check requirements
    setup.check_requirements()

    # Setup logging
    logger.setup_logging()

    # Get search info
    assets_dir = environment.get_locker_gaming_assets_root_dir()
    metadata_dir = environment.get_game_pegasus_metadata_root_dir()

    # Show preview
    if not args.no_preview:
        details = [
            "Assets dir: %s" % assets_dir,
            "Metadata dir: %s" % metadata_dir
        ]
        if not prompts.prompt_for_preview("Find missing game assets", details):
            logger.log_warning("Operation cancelled by user")
            return

    # Find all possible assets
    all_assets = set()
    for filename in paths.build_file_list(assets_dir):
        all_assets.add(filename)

    # Find missing assets
    found_assets = set()
    missing_assets = dict()
    for filename in paths.build_file_list(metadata_dir):
        if environment.is_game_metadata_file(filename):

            # Load metadata
            metadata_obj = metadata.Metadata()
            metadata_obj.import_from_metadata_file(filename)
            for game_platform in metadata_obj.get_sorted_platforms():
                for game_entry in metadata_obj.get_sorted_entries(game_platform):
                    for asset_type in config.AssetType.members():

                        # Get game info
                        game_name = game_entry.get_game()
                        game_supercategory, game_category, game_subcategory = gameinfo.derive_game_categories_from_platform(game_platform)

                        # Get asset file
                        asset_file = environment.get_locker_gaming_asset_file(game_category, game_subcategory, game_name, asset_type)

                        # Check if asset exists
                        if os.path.exists(asset_file):
                            found_assets.add(asset_file)
                        else:
                            if not asset_type in missing_assets:
                                missing_assets[asset_type] = set()
                            missing_assets[asset_type].add(asset_file)

    # Report and write missing assets
    for asset_type in config.AssetType.members():
        missing_items = sorted(missing_assets.get(asset_type, set()))
        reports.write_list_report(
            items = missing_items,
            title = "\nMissing '%s':" % asset_type.val(),
            max_display = 10 if args.verbose else 0,
            report_file = "Missing_%s.txt" % asset_type.val(),
            verbose = args.verbose,
            pretend_run = args.pretend_run)

    # Gather extra assets
    extra_assets = all_assets - found_assets
    for asset_type in config.AssetType.members():
        if asset_type in missing_assets:
            extra_assets = extra_assets - missing_assets[asset_type]

    # Report and write extra assets
    reports.write_list_report(
        items = sorted(extra_assets),
        title = "\nExtra assets:",
        max_display = 10 if args.verbose else 0,
        report_file = "Extras.txt",
        verbose = args.verbose,
        pretend_run = args.pretend_run)

# Start
if __name__ == "__main__":
    system.run_main(main)
