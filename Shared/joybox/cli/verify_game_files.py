# Imports
from joybox import environment
from joybox import system
from joybox import arguments
from joybox.collection import scanning
from joybox import setup
from joybox import logger
from joybox import prompts

# Build the argument parser
def build_parser():
    parser = arguments.ArgumentParser(command = "verify_game_files")
    parser.add_common_arguments()
    return parser

# After a preview, cross-check the game JSON, Pegasus metadata and hash files against the local locker's Gaming folder
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
        details = [
            "JSON dir: %s" % environment.get_game_json_metadata_root_dir(),
            "Metadata dir: %s" % environment.get_game_metadata_root_dir(),
            "Hashes dir: %s" % environment.get_game_hashes_metadata_root_dir()
        ]
        if not prompts.prompt_for_preview("Verify game files (check JSON, metadata, and hash files)", details):
            logger.log_warning("Operation cancelled by user")
            return

    # Check the json, metadata and hash files against the locker
    scanning.verify_game_files(
        verbose = args.verbose,
        exit_on_failure = args.exit_on_failure)

# Run through the shared error handling
def run():
    system.run_main(main)

# Start
if __name__ == "__main__":
    run()
