# Imports
from joybox import config
from joybox import system
from joybox import collection
from joybox import gamecollection
from joybox import arguments
from joybox import setup
from joybox import prompts

# Build the argument parser
def build_parser():
    parser = arguments.ArgumentParser(command = "backup_game_files")
    parser.add_group("Game selection")
    parser.add_game_supercategory_argument(description = "Supercategory of the games to back up")
    parser.add_game_category_argument(description = "Category of the games to back up; all categories when omitted in `Standard` mode")
    parser.add_game_subcategory_argument(description = "Subcategory (platform or store) of the games to back up; all of the category's subcategories when omitted in `Standard` mode")
    parser.add_game_name_argument(description = "Exact name of the game to back up; every game found when omitted in `Standard` mode")
    parser.add_generation_mode_argument(description = "`Standard` finds games in the JSON metadata; `Custom` takes exactly the game named by `-c`, `-s` and `-n`")
    parser.add_group("Output")
    parser.add_enum_argument(
        args = ("-l", "--locker_type"),
        arg_type = config.LockerType,
        description = "Locker to upload to; its passphrase encrypts the files")
    parser.add_common_arguments()
    return parser

# After a preview, download each selected store game whose build has changed and upload it, encrypted, to the locker
def main():

    # Parse arguments, check requirements and set up logging
    parser = build_parser()
    args = setup.start_command(parser)

    # Collect games to process
    games_to_process = list(gamecollection.iterate_selected_game_infos(
        parser = parser,
        generation_mode = args.generation_mode,
        verbose = args.verbose,
        exit_on_failure = args.exit_on_failure))

    # Show preview
    details = [game_info.get_name() for game_info in games_to_process]
    if not prompts.confirm_preview(args.no_preview, "Backup game files (store -> %s)" % args.locker_type, details):
        return

    # Backup game files
    collection.backup.backup_game_infos(
        game_infos = games_to_process,
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
