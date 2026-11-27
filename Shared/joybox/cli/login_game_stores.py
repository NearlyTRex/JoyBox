# Imports
from joybox import config
from joybox import system
from joybox import gamecollection
from joybox import collection
from joybox import arguments
from joybox import setup
from joybox import logger

# Build the argument parser
def build_parser():
    parser = arguments.ArgumentParser(command = "login_game_stores")
    parser.add_game_supercategory_argument(description = "Supercategory of the stores")
    parser.add_game_category_argument(description = "Category of the stores to log in to; all categories when omitted")
    parser.add_game_subcategory_argument(description = "Store subcategory, such as `Steam` or `GOG`; every subcategory of the selected categories when omitted")
    parser.add_enum_argument(
        args = ("-m", "--generation_mode"),
        arg_type = config.GenerationModeType,
        default = config.GenerationModeType.STANDARD,
        description = "How categories are selected: `Standard` walks the selected categories, `Custom` takes exactly the given category and subcategory")
    parser.add_common_arguments()
    return parser

# Log in to the store of each selected category and subcategory through its own command-line login
def main():

    # Parse arguments
    parser = build_parser()
    args, _ = parser.parse_known_args()

    # Check requirements
    setup.check_requirements()

    # Setup logging
    logger.setup_logging()

    # Login game stores
    for game_supercategory, game_category, game_subcategory in gamecollection.iterate_selected_game_categories(
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

# Run through the shared error handling
def run():
    system.run_main(main)

# Start
if __name__ == "__main__":
    run()
