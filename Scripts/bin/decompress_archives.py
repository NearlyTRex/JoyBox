#!/usr/bin/env python3

# Imports
import os, os.path
import sys

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.append(lib_folder)
import config
import system
import archive
import arguments
import setup
import logger
import paths
import prompts

# Parse arguments
parser = arguments.ArgumentParser(description = "Decompress archive files.")
parser.add_input_path_argument()
parser.add_enum_argument(
    args = ("-a", "--archive_types"),
    arg_type = config.ArchiveFileType,
    default = [config.ArchiveFileType.ZIP],
    description = "Archive types",
    allow_multiple = True)
parser.add_boolean_argument(args = ("-s", "--same_dir"), description = "Extract to same directory as original file")
parser.add_boolean_argument(args = ("-d", "--delete_originals"), description = "Delete original files")
parser.add_common_arguments()
args, unknown = parser.parse_known_args()

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Setup logging
    logger.setup_logging()

    # Get input path
    input_path = parser.get_input_path()

    # Show preview
    if not args.no_preview:
        details = [
            "Path: %s" % input_path,
            "Archive types: %s" % [t.cval() for t in args.archive_types],
            "Same dir: %s" % args.same_dir,
            "Delete originals: %s" % args.delete_originals
        ]
        if not prompts.prompt_for_preview("Decompress archives", details):
            logger.log_warning("Operation cancelled by user")
            return

    # Decompress archives
    archive_extensions = [archive_type.cval() for archive_type in args.archive_types]
    for file in paths.build_file_list_by_extensions(input_path, extensions = archive_extensions):

        # Get file info
        current_file = file
        file_dir = paths.get_filename_directory(current_file)
        file_basename = paths.get_filename_basename(current_file)
        output_dir = paths.join_paths(file_dir, file_basename)
        if args.same_dir:
            output_dir = file_dir

        # Decompress file
        archive.ExtractArchive(
            archive_file = current_file,
            extract_dir = output_dir,
            delete_original = args.delete_originals,
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure)

# Start
if __name__ == "__main__":
    system.run_main(main)
