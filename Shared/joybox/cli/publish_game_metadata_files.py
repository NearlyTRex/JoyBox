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
    parser = arguments.ArgumentParser(command = "publish_game_metadata_files")
    parser.add_common_arguments()
    return parser

# After a preview, render the Pegasus metadata of every ROM category as an HTML table page
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
        publish_dir = environment.get_game_published_metadata_root_dir()
        if not prompts.prompt_for_preview("Publish game metadata files to HTML", [publish_dir]):
            logger.log_warning("Operation cancelled by user")
            return

    # Publish game metadata files
    logger.log_info("Publishing game metadata files ...")
    success = collection.publish_all_game_metadata_entries(
        verbose = args.verbose,
        pretend_run = args.pretend_run,
        exit_on_failure = args.exit_on_failure)
    if not success:
        logger.log_error("Publishing metadata files failed", quit_program = True)

# Run through the shared error handling
def run():
    system.run_main(main)

# Start
if __name__ == "__main__":
    run()
