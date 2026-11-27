# Imports
from joybox import collection
from joybox import system
from joybox import arguments
from joybox import setup
from joybox import logger
from joybox import prompts

# Build the argument parser
def build_parser():
    parser = arguments.ArgumentParser(command = "clean_game_json_files")
    parser.add_common_arguments()
    return parser

# After a preview, rewrite every game JSON file with sorted keys and empty top-level values dropped
def main():

    # Parse arguments
    parser = build_parser()
    args, _ = parser.parse_known_args()

    # Check requirements
    setup.check_requirements()

    # Setup logging
    logger.setup_logging()

    # Collect json files to process
    json_files_to_process = collection.jsondata.find_existing_game_json_files()

    # Show preview
    if not args.no_preview:
        if not prompts.prompt_for_preview("Clean game JSON files (sort keys, remove empty values)", json_files_to_process):
            logger.log_warning("Operation cancelled by user")
            return

    # Clean json files
    collection.jsondata.clean_game_json_files(
        json_files = json_files_to_process,
        verbose = args.verbose,
        pretend_run = args.pretend_run,
        exit_on_failure = args.exit_on_failure)

# Run through the shared error handling
def run():
    system.run_main(main)

# Start
if __name__ == "__main__":
    run()
