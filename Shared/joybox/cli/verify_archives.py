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
    parser = arguments.ArgumentParser(
        description = "Test archive files for corruption with 7-Zip.",
        details = (
            "Finds every archive of the chosen types under the input path (or takes the one file\n"
            "given) and runs `7z t` on it, which reads every entry and checks its CRC. The run\n"
            "stops with an error at the first archive that fails.\n"
            "\n"
            "Nothing is written or changed."),
        examples = [
            ("Test every zip in a folder", "verify_archives -i /path/to/archives"),
            ("Test zip and 7z archives", "verify_archives -i /path/to/archives -a ZIP 7Z"),
        ],
        notes = [
            "Archives are matched by extension only, e.g. `ZIP` selects `.zip` files and `TAR_GZ` selects `.tar.gz` files.",
            "7-Zip must be installed as a JoyBox tool.",
        ],
        see_also = ["decompress_archives", "chdverify", "rezip_files"],
        section = "Files & Archives")
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
            "Archive types: %s" % [t.cval() for t in args.archive_types]
        ]
        if not prompts.prompt_for_preview("Verify archives", details):
            logger.log_warning("Operation cancelled by user")
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
