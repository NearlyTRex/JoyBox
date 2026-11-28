# Imports
from joybox import system
from joybox import gamecollection
from joybox import collection
from joybox import arguments
from joybox import setup
from joybox import prompts

# Build the argument parser
def build_parser():
    parser = arguments.ArgumentParser(command = "build_game_metadata_files")
    parser.add_game_supercategory_argument(description = "Supercategory of the games; only `Roms` produces metadata")
    parser.add_game_category_argument(description = "Category of the games to build; all categories when omitted")
    parser.add_game_subcategory_argument(description = "Subcategory (platform) of the games to build; every subcategory of the selected categories when omitted")
    parser.add_game_name_argument(description = "Build only the game with this exact name; every game with a JSON file when omitted")
    parser.add_generation_mode_argument()
    parser.add_common_arguments()
    return parser

# After a preview, add each selected game with a JSON file to its Pegasus metadata file and fetch its missing details
def main():

    # Parse arguments, check requirements and set up logging
    parser = build_parser()
    args = setup.start_command(parser)

    # Collect games to process
    games_to_process = collection.metadata.get_metadata_games(
        categories = gamecollection.iterate_selected_game_categories(
            parser = parser,
            generation_mode = args.generation_mode),
        game_name = args.game_name)

    # Show preview
    details = list({metadata_file for _, _, _, _, metadata_file in games_to_process})
    if not prompts.confirm_preview(args.no_preview, "Build game metadata files", details):
        return

    # Build metadata files
    collection.metadata.build_metadata_entries_for_games(
        games = games_to_process,
        verbose = args.verbose,
        pretend_run = args.pretend_run,
        exit_on_failure = args.exit_on_failure)

# Run through the shared error handling
def run():
    system.run_main(main)

# Start
if __name__ == "__main__":
    run()
