# Imports
from joybox import config
from joybox import archive
from joybox import system
from joybox import arguments
from joybox import setup
from joybox import logger
from joybox import prompts

# Build the argument parser
def build_parser():
    parser = arguments.ArgumentParser(command = "compress_folders")
    parser.add_input_path_argument(description = "Directory whose top-level folders are compressed; must exist")
    parser.add_enum_argument(
        args = ("-a", "--archive_type"),
        arg_type = config.ArchiveFileType,
        default = config.ArchiveFileType.ZIP,
        description = "Archive format to create; only `ZIP` and `7Z` are supported")
    parser.add_string_argument(args = ("-w", "--password"), description = "Password to encrypt the archives with; none when omitted")
    parser.add_string_argument(args = ("-s", "--volume_size"), description = "Split archives into volumes of this size, in 7-Zip's `-v` format such as `100m` or `4g`; not split when omitted")
    parser.add_boolean_argument(args = ("-d", "--delete_originals"), description = "Delete each folder after it is compressed")
    parser.add_common_arguments()
    return parser

# After a preview, compress each folder directly inside the input dir into its own 7-Zip archive, skipping existing archives
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
            "Archive type: %s" % args.archive_type,
            "Delete originals: %s" % args.delete_originals
        ]
        if not prompts.prompt_for_preview("Compress folders", details):
            logger.log_warning("Operation cancelled by user")
            return

    # Compress folders
    archive.archive_folders_in_directory(
        input_dir = input_path,
        archive_type = args.archive_type,
        password = args.password,
        volume_size = args.volume_size,
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
