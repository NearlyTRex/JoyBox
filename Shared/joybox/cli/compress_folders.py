# Imports
from joybox import archive
from joybox import system
from joybox import arguments
from joybox import setup
from joybox import prompts

# Build the argument parser
def build_parser():
    parser = arguments.ArgumentParser(command = "compress_folders")
    parser.add_input_path_argument(description = "Directory whose top-level folders are compressed; must exist")
    parser.add_archive_creation_arguments(delete_description = "Delete each folder after it is compressed")
    parser.add_common_arguments()
    return parser

# After a preview, compress each folder directly inside the input dir into its own 7-Zip archive, skipping existing archives
def main():

    # Parse arguments, check requirements and set up logging
    parser = build_parser()
    args = setup.start_command(parser)

    # Get input path and archive options
    input_path = parser.get_input_path()
    options = parser.get_archive_creation_options()

    # Show preview
    details = ["Path: %s" % input_path, "Archive type: %s" % options["archive_type"]]
    details.append("Delete originals: %s" % options["delete_originals"])
    if not prompts.confirm_preview(args.no_preview, "Compress folders", details):
        return

    # Compress folders
    archive.archive_folders_in_directory(
        input_dir = input_path,
        **options,
        verbose = args.verbose,
        pretend_run = args.pretend_run,
        exit_on_failure = args.exit_on_failure)

# Run through the shared error handling
def run():
    system.run_main(main)

# Start
if __name__ == "__main__":
    run()
