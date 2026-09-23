#!/usr/bin/env python3

# Imports
import os, os.path
import sys

# Custom imports
shared_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "..", "Shared"))
sys.path.append(shared_folder)
import joybox.config as config
import joybox.environment as environment
import joybox.system as system
import joybox.gameinfo as gameinfo
import joybox.collection as collection
import joybox.arguments as arguments
import joybox.setup as setup
import joybox.logger as logger

# Parse arguments
parser = arguments.ArgumentParser(
    description = "Log in to the selected game stores so their purchases, metadata and downloads can be fetched.",
    details = (
        "Picks stores by category and subcategory (for example `-c Computer -s Steam`); with no\n"
        "selection it goes through every subcategory. Subcategories without a store are skipped.\n"
        "For each store that is not already logged in, it runs the store's own command-line\n"
        "login, such as SteamCMD for Steam or Legendary for Epic Games, which may prompt for\n"
        "credentials.\n"
        "\n"
        "The session it leaves behind is what `build_game_store_purchases`,\n"
        "`build_game_metadata_files` and `download_game_metadata_assets` use when they talk\n"
        "to a store."),
    examples = [
        ("Log in to Steam", "login_game_stores -c Computer -s Steam"),
        ("Log in to the Epic Games store", "login_game_stores -c Computer -s \"Epic Games\""),
        ("Log in to every store", "login_game_stores"),
    ],
    notes = [
        "Stores sit under the `Roms` supercategory, which is the default, so `-u` is not needed.",
        "The store's login tool must be installed first; `setup_tools` installs them.",
    ],
    see_also = ["build_game_store_purchases", "build_game_metadata_files", "download_game_metadata_assets", "setup_tools"],
    section = "Game Collection")
parser.add_game_supercategory_argument(description = "Supercategory of the stores")
parser.add_game_category_argument(description = "Category of the stores to log in to; all categories when omitted")
parser.add_game_subcategory_argument(description = "Store subcategory, such as `Steam` or `GOG`; every subcategory of the selected categories when omitted")
parser.add_enum_argument(
    args = ("-m", "--generation_mode"),
    arg_type = config.GenerationModeType,
    default = config.GenerationModeType.STANDARD,
    description = "How categories are selected: `Standard` walks the selected categories, `Custom` takes exactly the given category and subcategory")
parser.add_common_arguments()
args, unknown = parser.parse_known_args()

# Main
def main():

    # Check requirements
    setup.check_requirements()

    # Setup logging
    logger.setup_logging()

    # Login game stores
    for game_supercategory, game_category, game_subcategory in gameinfo.iterate_selected_game_categories(
        parser = parser,
        generation_mode = args.generation_mode):
        success = collection.login_game_store(
            game_supercategory = game_supercategory,
            game_category = game_category,
            game_subcategory = game_subcategory,
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure)
        if not success:
            logger.log_error(
                message = "Login of store failed!",
                game_supercategory = game_supercategory,
                game_category = game_category,
                game_subcategory = game_subcategory,
                quit_program = True)

# Start
if __name__ == "__main__":
    system.run_main(main)
