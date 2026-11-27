# Imports
from joybox import system
from joybox import chd
from joybox import arguments
from joybox import setup
from joybox import logger
from joybox import prompts

# Build the argument parser
def build_parser():
    parser = arguments.ArgumentParser(command = "chdzip")
    parser.add_input_path_argument(description = "A `.chd` file, or a directory searched recursively for them; must exist")
    parser.add_boolean_argument(args = ("-d", "--delete_originals"), description = "Delete each CHD after its zip is written")
    parser.add_common_arguments()
    return parser

# After a preview, zip the files on each CHD's disc filesystem into a zip beside it, skipping CHDs already zipped
def main():

    # Parse arguments
    parser = build_parser()
    args, _ = parser.parse_known_args()

    # Check requirements
    setup.check_requirements()

    # Setup logging
    logger.setup_logging()

    # Get input path
    input_path = parser.get_input_path()

    # Show preview
    if not args.no_preview:
        details = [
            "Path: %s" % input_path,
            "Delete originals: %s" % args.delete_originals
        ]
        if not prompts.prompt_for_preview("CHD to ZIP", details):
            logger.log_warning("Operation cancelled by user")
            return

    # Archive chd files
    chd.archive_disc_chds(
        input_path = input_path,
        delete_originals = args.delete_originals,
        verbose = args.verbose,
        pretend_run = args.pretend_run,
        exit_on_failure = args.exit_on_failure)

# Run through the shared error handling
def run():
    system.run_main(main)

# Start
if __name__ == "__main__":
    run()
