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
import joybox.prompts as prompts

# Parse arguments
parser = arguments.ArgumentParser(
    description = "Import the games you own on a store as JSON and metadata entries, and refresh the existing ones.",
    details = (
        "Picks the store by category and subcategory (for example `-c Computer -s Steam`);\n"
        "subcategories without a store that can list purchases are skipped. For each store it\n"
        "fetches your current purchase list and runs two passes.\n"
        "\n"
        "Import: every purchase with no matching JSON file and not on the store's ignore list is\n"
        "shown and you are asked whether to import it (`y`), skip it (`n`) or ignore it for good\n"
        "(`i`). On import you choose the entry name, suggested from the store's title, and a\n"
        "JSON file seeded with the purchase data is created along with a metadata entry that\n"
        "carries the store URL when one is known.\n"
        "\n"
        "Update: every purchase that matches an existing JSON file has that file refreshed from\n"
        "the store, and its metadata entry filled in if it is missing downloadable fields."),
    examples = [
        ("Import Steam purchases", "build_game_store_purchases -c Computer -s Steam"),
        ("Import Epic Games purchases", "build_game_store_purchases -c Computer -s \"Epic Games\""),
        ("Reconcile purchases across every store", "build_game_store_purchases"),
        ("Dry run for the computer stores", "build_game_store_purchases -c Computer -p -v"),
    ],
    notes = [
        "The import pass is interactive: expect a prompt per new purchase, then one for its entry name.",
        "Ignored purchases are recorded in the subcategory's `ignores.json` next to its JSON files and are not offered again.",
        "Stores sit under the `Roms` supercategory, which is the default, so `-u` is not needed.",
        "Log in with `login_game_stores` first if the store session has expired.",
    ],
    see_also = ["login_game_stores", "build_game_json_files", "build_game_metadata_files", "scan_game_files"],
    section = "Game Collection")
parser.add_game_supercategory_argument(description = "Supercategory of the stores")
parser.add_game_category_argument(description = "Category of the stores to process; all categories when omitted")
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

    # Collect categories to process
    categories_to_process = []
    for game_supercategory, game_category, game_subcategory in gameinfo.iterate_selected_game_categories(
        parser = parser,
        generation_mode = args.generation_mode):
        categories_to_process.append((game_supercategory, game_category, game_subcategory))

    # Show preview
    if not args.no_preview:
        details = ["%s/%s/%s" % (sc, c, sub) for sc, c, sub in categories_to_process]
        if not prompts.prompt_for_preview("Build game store purchases", details):
            logger.log_warning("Operation cancelled by user")
            return

    # Build store purchases
    for game_supercategory, game_category, game_subcategory in categories_to_process:
        success = collection.build_game_store_purchases(
            game_supercategory = game_supercategory,
            game_category = game_category,
            game_subcategory = game_subcategory,
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure)
        if not success:
            logger.log_error(
                message = "Build of store purchases failed!",
                game_supercategory = game_supercategory,
                game_category = game_category,
                game_subcategory = game_subcategory,
                quit_program = True)

# Start
if __name__ == "__main__":
    system.run_main(main)
