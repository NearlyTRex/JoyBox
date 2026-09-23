#!/usr/bin/env python3

# Imports
import os, os.path
import sys

# Custom imports
shared_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "..", "Shared"))
sys.path.append(shared_folder)
import joybox.config as config
import joybox.system as system
import joybox.environment as environment
import joybox.collection as collection
import joybox.gameinfo as gameinfo
import joybox.metadata as metadata
import joybox.stores as stores
import joybox.manifest as manifest
import joybox.arguments as arguments
import joybox.setup as setup
import joybox.logger as logger
import joybox.prompts as prompts

# Parse arguments
parser = arguments.ArgumentParser(
    description = "Run the whole collection pipeline: store purchases, JSON files, metadata, optional assets, and HTML publishing.",
    details = (
        "Runs, in order, for the `Roms` supercategory of the selected categories:\n"
        "\n"
        "1. Load the Ludusavi manifest of game save locations, only with `-m`.\n"
        "2. Import and refresh store purchases, as `build_game_store_purchases` does.\n"
        "3. Build JSON files from the games in the `-l` locker, as `build_game_json_files` does.\n"
        "4. Build metadata entries, as `build_game_metadata_files` does.\n"
        "5. Download missing BoxFront and Video assets, only with `-a`.\n"
        "6. Publish the metadata to HTML, as `publish_game_metadata_files` does.\n"
        "\n"
        "Any failing step stops the run. Unlike the single-step tools, `-c` and `-s` here take\n"
        "comma-separated lists, and omitting them processes everything."),
    examples = [
        ("Run the pipeline for everything in the local locker", "scan_game_files -l Local"),
        ("Scan two categories", "scan_game_files -c Nintendo,Sony -l Local"),
        ("Scan two subcategories and download assets", "scan_game_files -s \"Nintendo Switch,Steam\" -l Local -a"),
        ("Load the manifest, then scan", "scan_game_files -m -l Local"),
        ("Dry run", "scan_game_files -l Local -p -v"),
    ],
    notes = [
        "The purchase step, and the asset step for non-store games, ask questions, so the run is interactive.",
        "Publishing always writes whole categories; `-s` does not narrow it.",
        "Unrecognised names in `-c` or `-s` are dropped silently, and if none are left every category or subcategory is processed.",
    ],
    see_also = ["build_game_store_purchases", "build_game_json_files", "build_game_metadata_files", "download_game_metadata_assets", "publish_game_metadata_files"],
    section = "Game Collection")
parser.add_group("Selection")
parser.add_enum_argument(
    args = ("-l", "--locker_type"),
    arg_type = config.LockerType,
    description = "Locker to list games from and read their files in for the JSON step; Local when omitted")
parser.add_string_argument(args = ("-k", "--keys"), description = "Comma-separated metadata keys. Not used by any step")
parser.add_enum_list_argument(args = ("-c", "--categories"), arg_type = config.Category, description = "Categories to process; all when omitted")
parser.add_enum_list_argument(args = ("-s", "--subcategories"), arg_type = config.Subcategory, description = "Subcategories to process; every subcategory of the selected categories when omitted")
parser.add_group("Steps")
parser.add_boolean_argument(args = ("-a", "--download_assets"), description = "Also download missing BoxFront and Video assets for each game")
parser.add_boolean_argument(args = ("-m", "--load_manifest"), description = "Load the Ludusavi manifest of game save locations before the first step")
parser.add_common_arguments()
args, unknown = parser.parse_known_args()

# Main
def main():

    # Check requirements
    setup.check_requirements()

    # Setup logging
    logger.setup_logging()

    # Log filtering if specified
    if args.categories:
        category_names = [c for c in args.categories.split(",")]
        logger.log_info(f"Filtering to categories: {args.categories}")
    if args.subcategories:
        logger.log_info(f"Filtering to subcategories: {args.subcategories}")

    # Show preview
    if not args.no_preview:
        details = [
            "JSON dir: %s" % environment.get_game_json_metadata_root_dir(),
            "Metadata dir: %s" % environment.get_game_metadata_root_dir(),
            "Published dir: %s" % environment.get_game_published_metadata_root_dir()
        ]
        if not prompts.prompt_for_preview("Scan game files (build store purchases, JSON, metadata, publish)", details):
            logger.log_warning("Operation cancelled by user")
            return

    # Load manifest
    if args.load_manifest:
        logger.log_info("Loading manifest ...")
        manifest.get_manifest_instance().load(
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure)

    # Build game store purchases
    logger.log_info("Building store purchases ...")
    success = collection.build_all_game_store_purchases(
        categories = args.categories,
        subcategories = args.subcategories,
        verbose = args.verbose,
        pretend_run = args.pretend_run,
        exit_on_failure = args.exit_on_failure)
    if not success:
        logger.log_error("Building store purchases failed", quit_program = True)

    # Build game json files
    logger.log_info("Building json files ...")
    success = collection.build_all_game_json_files(
        locker_type = args.locker_type,
        categories = args.categories,
        subcategories = args.subcategories,
        verbose = args.verbose,
        pretend_run = args.pretend_run,
        exit_on_failure = args.exit_on_failure)
    if not success:
        logger.log_error("Building json files failed", quit_program = True)

    # Build game metadata files
    logger.log_info("Building metadata files ...")
    success = collection.build_all_game_metadata_entries(
        categories = args.categories,
        subcategories = args.subcategories,
        verbose = args.verbose,
        pretend_run = args.pretend_run,
        exit_on_failure = args.exit_on_failure)
    if not success:
        logger.log_error("Building metadata files failed", quit_program = True)

    # Download game metadata assets
    if args.download_assets:
        logger.log_info("Downloading metadata assets ...")
        success = collection.download_all_metadata_assets(
            categories = args.categories,
            subcategories = args.subcategories,
            skip_existing = True,
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure)
        if not success:
            logger.log_error("Downloading metadata assets failed", quit_program = True)

    # Publish game metadata files
    logger.log_info("Publishing metadata files ...")
    success = collection.publish_all_game_metadata_entries(
        categories = args.categories,
        subcategories = args.subcategories,
        verbose = args.verbose,
        pretend_run = args.pretend_run,
        exit_on_failure = args.exit_on_failure)
    if not success:
        logger.log_error("Publishing metadata files failed", quit_program = True)

# Start
if __name__ == "__main__":
    system.run_main(main)
