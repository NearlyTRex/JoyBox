# Imports
from joybox import config
from joybox import system
from joybox import archive
from joybox import arguments
from joybox import setup
from joybox import prompts

# Build the argument parser
def build_parser():
    parser = arguments.ArgumentParser(command = "decompress_archives")
    parser.add_input_path_argument(description = "An archive file, or a directory searched recursively for archives; must exist")
    parser.add_enum_argument(
        args = ("-a", "--archive_types"),
        arg_type = config.ArchiveFileType,
        default = [config.ArchiveFileType.ZIP],
        description = "Archive types to extract, space separated; each selects files by its extension",
        allow_multiple = True)
    parser.add_boolean_argument(args = ("-s", "--same_dir"), description = "Extract into the archive's own directory instead of a `<name>` folder")
    parser.add_boolean_argument(args = ("-d", "--delete_originals"), description = "Delete each archive after it is extracted")
    parser.add_common_arguments()
    return parser

# After a preview, extract each archive of the chosen types under the input into a folder beside it, or into its own dir
def main():

    # Parse arguments, check requirements and set up logging
    parser = build_parser()
    args = setup.start_command(parser)

    # Get input path
    input_path = parser.get_input_path()

    # Show preview
    details = [
        "Path: %s" % input_path,
        "Archive types: %s" % [t.cval() for t in args.archive_types],
        "Same dir: %s" % args.same_dir,
        "Delete originals: %s" % args.delete_originals
    ]
    if not prompts.confirm_preview(args.no_preview, "Decompress archives", details):
        return

    # Decompress archives
    archive.extract_archives_by_type(
        input_path = input_path,
        archive_types = args.archive_types,
        same_dir = args.same_dir,
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
