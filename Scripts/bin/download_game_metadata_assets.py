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
import joybox.arguments as arguments
import joybox.setup as setup
import joybox.logger as logger
import joybox.prompts as prompts

# Parse arguments
parser = arguments.ArgumentParser(
    description = "Download one kind of artwork or video for each selected game and back it up to the lockers.",
    details = (
        "For each selected game with a JSON file, finds a URL for the `-t` asset type. Store\n"
        "games ask their store. Other games are searched on Google Images, YouTube, Steam and\n"
        "SteamGridDB, the candidates are listed, and you pick one by number or paste your own\n"
        "URL.\n"
        "\n"
        "The file is downloaded to a temporary directory, converted and cleaned to the asset\n"
        "type's format (`.jpg` for images, `.png` for labels, `.mp4` for video), then backed up\n"
        "to `Gaming/Assets/<category>/<subcategory>/<asset type>/<game name><ext>` in the `-l`\n"
        "locker, or in every configured locker with `All`."),
    examples = [
        ("Download box fronts for a platform to the local locker", "download_game_metadata_assets -c Nintendo -s \"Nintendo Switch\" -t BoxFront -l Local"),
        ("Download one game's screenshot", "download_game_metadata_assets -c Computer -s Steam -n \"Hades (World)\" -t Screenshot -l Local"),
        ("Download only the box fronts that are missing", "download_game_metadata_assets -c Sony -s \"Sony PlayStation 2\" -t BoxFront -e -l Local"),
        ("Dry run for a platform", "download_game_metadata_assets -c Nintendo -s \"Nintendo Switch\" -t BoxFront -p -v"),
    ],
    notes = [
        "Non-store games need a choice for each asset, so expect a prompt per game.",
        "`-e` looks for the asset in the Local locker's assets folder, whichever locker `-l` names.",
        "Log in with `login_game_stores` first if a store session has expired.",
    ],
    see_also = ["find_missing_game_assets", "build_game_metadata_files", "login_game_stores", "scan_game_files"],
    section = "Game Collection")
parser.add_group("Selection")
parser.add_game_supercategory_argument(description = "Supercategory of the games")
parser.add_game_category_argument(description = "Category of the games; all categories when omitted")
parser.add_game_subcategory_argument(description = "Subcategory (platform) of the games; every subcategory of the selected categories when omitted")
parser.add_game_name_argument(description = "Download only for the game with this exact name; every game with a JSON file when omitted")
parser.add_enum_argument(
    args = ("-t", "--asset_type"),
    arg_type = config.AssetType,
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
args, unknown = parser.parse_known_args()

# Main
def main():

    # Check requirements
    setup.check_requirements()

    # Setup logging
    logger.setup_logging()

    # Collect games to process
    games_to_process = []
    for game_info in gameinfo.iterate_selected_game_infos(
        parser = parser,
        generation_mode = args.generation_mode,
        verbose = args.verbose,
        pretend_run = args.pretend_run,
        exit_on_failure = args.exit_on_failure):
        games_to_process.append(game_info)

    # Show preview
    if not args.no_preview:
        details = [environment.get_locker_gaming_assets_root_dir()]
        asset_desc = args.asset_type if args.asset_type else "all types"
        if not prompts.prompt_for_preview("Download metadata assets (%s)" % asset_desc, details):
            logger.log_warning("Operation cancelled by user")
            return

    # Download metadata assets
    for game_info in games_to_process:
        success = collection.download_metadata_asset(
            game_info = game_info,
            asset_type = args.asset_type,
            skip_existing = args.skip_existing,
            locker_type = args.locker_type,
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure)
        if not success:
            logger.log_error(
                message = "Download of metadata assets failed!",
                game_supercategory = game_info.get_supercategory(),
                game_category = game_info.get_category(),
                game_subcategory = game_info.get_subcategory(),
                game_name = game_info.get_name(),
                quit_program = True)

# Start
if __name__ == "__main__":
    system.run_main(main)
