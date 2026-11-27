# Imports
from joybox import config
from joybox import environment
from joybox import metadata
from joybox import system
from joybox import arguments
from joybox import setup
from joybox import logger
from joybox import prompts

# Build the argument parser
def build_parser():
    parser = arguments.ArgumentParser(command = "find_missing_game_metadata")
    parser.add_enum_argument(
        args = ("-k", "--keys"),
        arg_type = config.MetadataKeyType,
        default = config.MetadataKeyType.DOWNLOADABLE,
        description = "Which set of metadata fields to check")
    parser.add_common_arguments()
    return parser

# After a preview, log and write per key the Pegasus metadata entries missing the chosen fields
def main():

    # Parse arguments
    parser = build_parser()
    args, _ = parser.parse_known_args()

    # Check requirements
    setup.check_requirements()

    # Setup logging
    logger.setup_logging()

    # Get metadata dir
    metadata_dir = environment.get_game_pegasus_metadata_root_dir()

    # Determine keys to check
    keys_to_check = metadata.get_metadata_keys_to_check(args.keys)

    # Show preview
    if not args.no_preview:
        details = [
            "Metadata dir: %s" % metadata_dir,
            "Keys to check: %s" % ", ".join(keys_to_check)
        ]
        if not prompts.prompt_for_preview("Find missing game metadata", details):
            logger.log_warning("Operation cancelled by user")
            return

    # Report missing metadata
    metadata.report_missing_game_metadata(
        metadata_dir = metadata_dir,
        keys_to_check = keys_to_check,
        verbose = args.verbose,
        pretend_run = args.pretend_run)

# Run through the shared error handling
def run():
    system.run_main(main)

# Start
if __name__ == "__main__":
    run()
