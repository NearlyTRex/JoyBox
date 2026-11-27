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
    parser = arguments.ArgumentParser(command = "clean_game_hash_files")
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
