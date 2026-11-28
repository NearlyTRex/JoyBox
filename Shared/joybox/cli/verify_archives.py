# Imports
from joybox import config
from joybox import system
from joybox import archive
from joybox import arguments
from joybox import setup
from joybox import logger
from joybox import paths
from joybox import prompts

# Build the argument parser
def build_parser():
    parser = arguments.ArgumentParser(command = "verify_archives")
    parser.add_input_path_argument(description = "An archive file, or a directory searched recursively for archives; must exist")
    parser.add_enum_argument(
        args = ("-a", "--archive_types"),
        arg_type = config.ArchiveFileType,
        default = [config.ArchiveFileType.ZIP],
        description = "Archive types to test, space separated; each selects files by its extension",
        allow_multiple = True)
    parser.add_common_arguments()
    return parser

# After a preview, test each archive of the chosen types under the input with 7-Zip; stops at the first that fails
def main():

    # Parse arguments, check requirements and set up logging
    parser = build_parser()
    args = setup.start_command(parser)

    # Get input path
    input_path = parser.get_input_path()

    # Show preview
    details = [
        "Path: %s" % input_path,
        "Archive types: %s" % [t.cval() for t in args.archive_types]
    ]
    if not prompts.confirm_preview(args.no_preview, "Verify archives", details):
        return

    # Verify archives
    archive_extensions = [archive_type.cval() for archive_type in args.archive_types]
    for file in paths.build_file_list_by_extensions(input_path, extensions = archive_extensions):
        logger.log_info("Verifying %s ..." % file)
        verification_success = archive.test_archive(
            archive_file = file,
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure)
        if verification_success:
            logger.log_info("Verified!")
        else:
            logger.log_error("Verification failed!", quit_program = True)

# Run through the shared error handling
def run():
    system.run_main(main)

# Start
if __name__ == "__main__":
    run()
