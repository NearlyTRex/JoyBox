#!/usr/bin/env python3

# Imports
import os, os.path
import sys

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.append(lib_folder)
import config
import system
import environment
import collection
import gameinfo
import arguments
import setup
import logger

# Parse arguments
parser = arguments.ArgumentParser(description = "Download metadata assets.")
parser.add_game_supercategory_argument()
parser.add_game_category_argument()
parser.add_game_subcategory_argument()
parser.add_game_name_argument()
parser.add_enum_argument(
    args = ("-t", "--asset_type"),
    arg_type = config.AssetType,
    description = "Asset type")
parser.add_enum_argument(
    args = ("-m", "--generation_mode"),
    arg_type = config.GenerationModeType,
    default = config.GenerationModeType.STANDARD,
    description = "Generation mode")
parser.add_boolean_argument(args = ("-e", "--skip_existing"), description = "Skip existing files")
parser.add_enum_argument(
    args = ("-k", "--locker_type"),
    arg_type = config.LockerType,
    default = config.LockerType.ALL,
    description = "Locker type for backup upload")
parser.add_common_arguments()
args, unknown = parser.parse_known_args()

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Setup logging
    logger.setup_logging()

    # Collect games to process
    games_to_process = []
    for game_info in gameinfo.IterateSelectedGameInfos(
        parser = parser,
        generation_mode = args.generation_mode,
        verbose = args.verbose,
        pretend_run = args.pretend_run,
        exit_on_failure = args.exit_on_failure):
        games_to_process.append(game_info)

    # Show preview
    if not args.no_preview:
        details = [environment.GetLockerGamingAssetsRootDir()]
        asset_desc = args.asset_type if args.asset_type else "all types"
        if not system.PromptForPreview("Download metadata assets (%s)" % asset_desc, details):
            logger.log_warning("Operation cancelled by user")
            return

    # Download metadata assets
    for game_info in games_to_process:
        success = collection.DownloadMetadataAsset(
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
    system.RunMain(main)
