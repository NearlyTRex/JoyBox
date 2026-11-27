# Imports
from joybox import config
from joybox import system
from joybox import environment
from joybox import arguments
from joybox.collection import scanning
from joybox import setup
from joybox import logger
from joybox import prompts

# Build the argument parser
def build_parser():
    parser = arguments.ArgumentParser(command = "scan_game_files")
    parser.add_group("Selection")
    parser.add_enum_argument(
        args = ("-l", "--locker_type"),
        arg_type = config.LockerType,
        description = "Locker to list games from and read their files in for the JSON step; Local when omitted")
    parser.add_string_argument(args = ("-k", "--keys"), description = "Comma-separated metadata keys. Not used by any step")
    parser.add_enum_list_argument(args = ("-c", "--categories"), arg_type = config.Category, description = "Categories to process; all when omitted")
    parser.add_enum_list_argument(args = ("-s", "--subcategories"), arg_type = config.Subcategory, description = "Subcategories to process; every subcategory of the selected categories when omitted")
    parser.add_group("Steps")
    parser.add_boolean_argument(args = ("--skip_purchases"), description = "Skip importing and refreshing store purchases, and build metadata and assets only for the games in the `-l` locker")
    parser.add_boolean_argument(args = ("-a", "--download_assets"), description = "Also download missing BoxFront and Video assets for each game")
    parser.add_boolean_argument(args = ("-m", "--load_manifest"), description = "Load the Ludusavi manifest of game save locations before the first step")
    parser.add_boolean_argument(args = ("--create_playlists"), description = "In the JSON step, write a `.m3u` playlist into the folder of each multi-disc game that has none; off by default so read-only lockers are left untouched")
    parser.add_common_arguments()
    return parser

# After a preview, import store purchases, then build JSON files and metadata, optionally download assets, and publish the HTML pages
def main():

    # Parse arguments
    parser = build_parser()
    args, _ = parser.parse_known_args()

    # Check requirements
    setup.check_requirements()

    # Setup logging
    logger.setup_logging()

    # Reject unknown filter values, then log the filters
    scanning.check_scan_filters(args.categories, args.subcategories)

    # Show preview
    if not args.no_preview:
        details = [
            "JSON dir: %s" % environment.get_game_json_metadata_root_dir(),
            "Metadata dir: %s" % environment.get_game_metadata_root_dir(),
            "Published dir: %s" % environment.get_game_published_metadata_root_dir(),
            "Store purchases: %s" % ("skipped" if args.skip_purchases else "imported and refreshed")
        ]
        if not prompts.prompt_for_preview("Scan game files (build store purchases, JSON, metadata, publish)", details):
            logger.log_warning("Operation cancelled by user")
            return

    # Build, then publish, the game files
    scanning.scan_game_files(
        categories = args.categories,
        subcategories = args.subcategories,
        locker_type = args.locker_type,
        skip_purchases = args.skip_purchases,
        load_manifest = args.load_manifest,
        create_playlists = args.create_playlists,
        download_assets = args.download_assets,
        verbose = args.verbose,
        pretend_run = args.pretend_run,
        exit_on_failure = args.exit_on_failure)

# Run through the shared error handling
def run():
    system.run_main(main)

# Start
if __name__ == "__main__":
    run()
