# Imports
from joybox import system
from joybox import environment
from joybox import collection
from joybox import arguments
from joybox import setup
from joybox import logger
from joybox import prompts

# Build the argument parser
def build_parser():
    parser = arguments.ArgumentParser(
        description = "Rewrite every game hash file with its entries in sorted order.",
        details = (
            "Reads each per-subcategory hash file under `Hashes/` in the game metadata repository\n"
            "and writes it back with entries sorted by path and keys sorted within each entry, so\n"
            "the files stay stable under version control.\n"
            "\n"
            "Reading a file also adds any missing encrypted-field keys (`filename_enc`, `hash_enc`,\n"
            "`size_enc`), and entries with the same directory and file name collapse into one."),
        examples = [
            ("Sort every hash file", "clean_game_hash_files"),
            ("Sort without the confirmation prompt", "clean_game_hash_files --no-preview"),
            ("Show which files would be sorted", "clean_game_hash_files -p -v"),
        ],
        notes = [
            "There are no selection options; every hash file for every supercategory is processed.",
        ],
        see_also = ["build_game_hash_files", "verify_game_files", "clean_game_json_files", "clean_game_metadata_files"],
        section = "Game Collection")
    parser.add_common_arguments()
    return parser

# After a preview, rewrite every game hash file with its entries sorted
def main():

    # Parse arguments
    parser = build_parser()
    args, _ = parser.parse_known_args()

    # Check requirements
    setup.check_requirements()

    # Setup logging
    logger.setup_logging()

    # Show preview
    if not args.no_preview:
        details = [environment.get_game_hashes_metadata_root_dir()]
        if not prompts.prompt_for_preview("Clean game hash files (sort entries)", details):
            logger.log_warning("Operation cancelled by user")
            return

    # Sort hash files
    success = collection.sort_all_hash_files(
        verbose = args.verbose,
        pretend_run = args.pretend_run,
        exit_on_failure = args.exit_on_failure)
    if not success:
        logger.log_error("Sort of hash file failed!", quit_program = True)

# Run through the shared error handling
def run():
    system.run_main(main)

# Start
if __name__ == "__main__":
    run()
