# Imports
from joybox import config
from joybox import system
from joybox import arguments
from joybox.collection import saves
from joybox import setup
from joybox import logger
from joybox import prompts

# Build the argument parser
def build_parser():
    parser = arguments.ArgumentParser(command = "save_game_tool")
    parser.add_group("Action")
    parser.add_input_path_argument(description = "Not used by any action")
    parser.add_enum_argument(
        args = ("-a", "--action"),
        arg_type = config.SaveActionType,
        default = config.SaveActionType.PACK,
        description = "What to do with each selected game's saves; see the list above")
    parser.add_group("Game selection")
    parser.add_game_category_argument(description = "Category of the games to process; every category when omitted")
    parser.add_game_subcategory_argument(description = "Subcategory (platform or store) of the games to process; every subcategory of the category when omitted")
    parser.add_game_name_argument(description = "Exact name of the game to process; every game when omitted")
    parser.add_group("Output")
    parser.add_enum_argument(
        args = ("-l", "--locker_type"),
        arg_type = config.LockerType,
        default = config.LockerType.ALL,
        description = "Locker to copy new archives to for `Pack` and `Export`, besides the local locker; `All` means every configured locker")
    parser.add_common_arguments()
    return parser

# After a preview, pack, unpack, import or export the save, or import the save paths, on each selected game with a JSON entry
def main():

    # Parse arguments
    parser = build_parser()
    args, _ = parser.parse_known_args()

    # Check requirements
    setup.check_requirements()

    # Setup logging
    logger.setup_logging()

    # Collect games to process; games with nothing to pack or unpack are skipped
    games_to_process = saves.get_save_action_games(
        parser = parser,
        action = args.action,
        verbose = args.verbose,
        exit_on_failure = args.exit_on_failure)

    # Show preview
    if not args.no_preview:
        details = ["%s/%s/%s" % (g.get_category(), g.get_subcategory(), g.get_name()) for g in games_to_process]
        if not prompts.prompt_for_preview("Save game %s" % args.action, details):
            logger.log_warning("Operation cancelled by user")
            return

    # Process games
    saves.run_save_action(
        games = games_to_process,
        action = args.action,
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
