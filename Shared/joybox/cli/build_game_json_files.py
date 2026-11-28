# Imports
from joybox import config
from joybox import system
from joybox import gamecollection
from joybox import collection
from joybox import arguments
from joybox import setup
from joybox import prompts
from joybox import paths

# Build the argument parser
def build_parser():
    parser = arguments.ArgumentParser(command = "build_game_json_files")
    parser.add_group("Input")
    parser.add_input_path_argument(description = "Directory holding the game's files, used instead of the locker directory")
    parser.add_group("Selection")
    parser.add_game_supercategory_argument(description = "Supercategory of the games to build")
    parser.add_game_category_argument(description = "Category of the games to build; all categories when omitted")
    parser.add_game_subcategory_argument(description = "Subcategory (platform) of the games to build; every subcategory of the selected categories when omitted")
    parser.add_game_name_argument(description = "Build only the game with this exact folder name; every game in the locker when omitted")
    parser.add_enum_argument(
        args = ("-l", "--locker_type"),
        arg_type = config.LockerType,
        description = "Locker to list games from and read their files in; Local when omitted")
    parser.add_generation_mode_argument()
    parser.add_string_argument(
        args = ("-b", "--locker_base_dir"),
        default = None,
        description = "Locker root to list and read games from instead of the `-l` locker's mount path (its Gaming folder is used)")
    parser.add_group("Output")
    parser.add_boolean_argument(args = ("--create_playlists",), description = "Write a `.m3u` playlist into the folder of each multi-disc `Roms` game that has none; off by default so read-only lockers are left untouched")
    parser.add_common_arguments()
    return parser

# After a preview, create or refresh the JSON file of each selected game found in the locker
def main():

    # Parse arguments, check requirements and set up logging
    parser = build_parser()
    args = setup.start_command(parser)

    # Get locker base dir
    locker_base_dir = paths.expand_path(args.locker_base_dir) if args.locker_base_dir else None

    # Collect games to process
    games_to_process = collection.jsondata.get_json_build_games(
        categories = gamecollection.iterate_selected_game_categories(
            parser = parser,
            generation_mode = args.generation_mode),
        game_name = args.game_name,
        input_path = parser.get_input_path(check_exists = False),
        locker_type = args.locker_type,
        locker_base_dir = locker_base_dir)

    # Show preview
    details = [json_file for _, _, _, _, _, json_file in games_to_process]
    if not prompts.confirm_preview(args.no_preview, "Build game JSON files (source: %s)" % args.locker_type, details):
        return

    # Build json files
    collection.jsondata.build_json_files_for_games(
        games = games_to_process,
        locker_type = args.locker_type,
        create_disc_playlists = args.create_playlists,
        verbose = args.verbose,
        pretend_run = args.pretend_run,
        exit_on_failure = args.exit_on_failure)

# Run through the shared error handling
def run():
    system.run_main(main)

# Start
if __name__ == "__main__":
    run()
