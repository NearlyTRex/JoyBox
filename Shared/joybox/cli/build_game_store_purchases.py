# Imports
from joybox import config
from joybox import system
from joybox import gamecollection
from joybox import collection
from joybox import arguments
from joybox import setup
from joybox import logger
from joybox import prompts

# Build the argument parser
def build_parser():
    parser = arguments.ArgumentParser(command = "build_game_store_purchases")
    parser.add_game_supercategory_argument(description = "Supercategory of the stores")
    parser.add_game_category_argument(description = "Category of the stores to process; all categories when omitted")
    parser.add_game_subcategory_argument(description = "Store subcategory, such as `Steam` or `GOG`; every subcategory of the selected categories when omitted")
    parser.add_enum_argument(
        args = ("-m", "--generation_mode"),
        arg_type = config.GenerationModeType,
        default = config.GenerationModeType.STANDARD,
        description = "How categories are selected: `Standard` walks the selected categories, `Custom` takes exactly the given category and subcategory")
    parser.add_common_arguments()
    return parser

# After a preview, import new purchases from the selected stores as JSON and metadata entries and refresh the known ones
def main():

    # Parse arguments
    parser = build_parser()
    args, _ = parser.parse_known_args()

    # Check requirements
    setup.check_requirements()

    # Setup logging
    logger.setup_logging()

    # Collect categories to process
    categories_to_process = list(gamecollection.iterate_selected_game_categories(
        parser = parser,
        generation_mode = args.generation_mode))

    # Show preview
    if not args.no_preview:
        details = ["%s/%s/%s" % (sc, c, sub) for sc, c, sub in categories_to_process]
        if not prompts.prompt_for_preview("Build game store purchases", details):
            logger.log_warning("Operation cancelled by user")
            return

    # Build store purchases
    collection.purchase.build_store_purchases_for_categories(
        categories = categories_to_process,
        verbose = args.verbose,
        pretend_run = args.pretend_run,
        exit_on_failure = args.exit_on_failure)

# Run through the shared error handling
def run():
    system.run_main(main)

# Start
if __name__ == "__main__":
    run()
