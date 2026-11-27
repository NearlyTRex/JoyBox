# Imports
from joybox import system
from joybox import archive
from joybox import arguments
from joybox import setup
from joybox import logger
from joybox import prompts

# Build the argument parser
def build_parser():
    parser = arguments.ArgumentParser(command = "rezip_files")
    parser.add_input_path_argument(description = "A `.zip` file, or a directory searched recursively for them; must exist")
    parser.add_common_arguments()
    return parser

# After a preview, rebuild each zip under the input in place with fixed, reproducible 7-Zip settings
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
        details = ["Path: %s" % input_path]
        if not prompts.prompt_for_preview("Rezip files deterministically", details):
            logger.log_warning("Operation cancelled by user")
            return

    # Rezip zip files
    archive.rezip_archives(
        input_path = input_path,
        verbose = args.verbose,
        pretend_run = args.pretend_run,
        exit_on_failure = args.exit_on_failure)

# Run through the shared error handling
def run():
    system.run_main(main)

# Start
if __name__ == "__main__":
    run()
