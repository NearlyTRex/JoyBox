#!/usr/bin/env python3

# Imports
import os, os.path
import sys

# Custom imports
shared_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "..", "Shared"))
sys.path.append(shared_folder)
import joybox.config as config
import joybox.environment as environment
import joybox.metadata as metadata
import joybox.gameinfo as gameinfo
import joybox.system as system
import joybox.arguments as arguments
import joybox.setup as setup
import joybox.logger as logger
import joybox.paths as paths
import joybox.prompts as prompts
import joybox.reports as reports

# Parse arguments
parser = arguments.ArgumentParser(
    description = "Compare the games in the Pegasus metadata with the asset files in the local locker.",
    details = (
        "For every entry in every Pegasus metadata file, checks whether each asset type\n"
        "(Background, BoxBack, BoxFront, Label, Screenshot, Video) exists at its expected path\n"
        "under the Local locker's `Gaming/Assets` folder. It then reports the missing assets per\n"
        "type, and the extra files in the assets folder that no metadata entry accounts for.\n"
        "\n"
        "Each non-empty list is written in full to a file in the current directory:\n"
        "`Missing_<AssetType>.txt` and `Extras.txt`. The log shows only the totals, or the first\n"
        "and last few items with `-v`."),
    examples = [
        ("Report missing and extra assets", "find_missing_game_assets"),
        ("Also show sample items in the log", "find_missing_game_assets -v"),
        ("Report without writing the list files", "find_missing_game_assets -p -v"),
    ],
    notes = [
        "Run it from a scratch directory; the report files land in whatever directory you run it from and overwrite earlier ones.",
    ],
    see_also = ["download_game_metadata_assets", "find_missing_game_metadata"],
    section = "Game Collection")
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
