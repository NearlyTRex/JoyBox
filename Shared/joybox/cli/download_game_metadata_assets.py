# Imports
from joybox import config
from joybox import system
from joybox import environment
from joybox import collection
from joybox import gamecollection
from joybox import arguments
from joybox import setup
from joybox import logger
from joybox import prompts

# Build the argument parser
def build_parser():
    parser = arguments.ArgumentParser(command = "download_game_metadata_assets")
    parser.add_group("Selection")
    parser.add_game_supercategory_argument(description = "Supercategory of the games")
    parser.add_game_category_argument(description = "Category of the games; all categories when omitted")
    parser.add_game_subcategory_argument(description = "Subcategory (platform) of the games; every subcategory of the selected categories when omitted")
    parser.add_game_name_argument(description = "Download only for the game with this exact name; every game with a JSON file when omitted")
    parser.add_enum_argument(
        args = ("-t", "--asset_type"),
        arg_type = config.AssetType,
        required = True,
        description = "Kind of asset to download")
    parser.add_enum_argument(
        args = ("-m", "--generation_mode"),
        arg_type = config.GenerationModeType,
        default = config.GenerationModeType.STANDARD,
        description = "How games are selected: `Standard` walks the selected categories, `Custom` takes exactly the given category, subcategory and name")
    parser.add_group("Behavior")
    parser.add_boolean_argument(args = ("-e", "--skip_existing"), description = "Skip games that already have this asset, and do not overwrite files already in the destination locker")
    parser.add_enum_argument(
        args = ("-l", "--locker_type"),
        arg_type = config.LockerType,
        default = config.LockerType.ALL,
        description = "Locker to back the asset up to; `All` means every configured locker")
    parser.add_common_arguments()
    return parser

# After a preview, download the chosen asset type for each selected game and back it up to the lockers
def main():

    # Parse arguments
    parser = build_parser()
    args, _ = parser.parse_known_args()

    # Check requirements
    setup.check_requirements()

    # Setup logging
    logger.setup_logging()

    # Collect games to process
    games_to_process = []
    for game_info in gamecollection.iterate_selected_game_infos(
        parser = parser,
        generation_mode = args.generation_mode,
        verbose = args.verbose,
        exit_on_failure = args.exit_on_failure):
        games_to_process.append(game_info)

    # Show preview
    if not args.no_preview:
        details = [environment.get_locker_gaming_assets_root_dir()]
        if not prompts.prompt_for_preview("Download metadata assets (%s)" % args.asset_type, details):
            logger.log_warning("Operation cancelled by user")
            return

    # Download metadata assets
    collection.asset.download_metadata_asset_for_games(
        game_infos = games_to_process,
        asset_type = args.asset_type,
        skip_existing = args.skip_existing,
        locker_type = args.locker_type,
        verbose = args.verbose,
        pretend_run = args.pretend_run,
        exit_on_failure = args.exit_on_failure)

# Run through the shared error handling
def run():
    system.run_main(main)

# Start
if __name__ == "__main__":
    run()
