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
parser = arguments.ArgumentParser(description = "Compress files.")
parser.add_input_path_argument()
parser.add_enum_argument(
    args = ("-a", "--archive_type"),
    arg_type = config.ArchiveFileType,
    default = config.ArchiveFileType.ZIP,
    description = "Archive type")
parser.add_string_argument(args = ("-w", "--password"), description = "Password to set")
parser.add_string_argument(args = ("-s", "--volume_size"), description = "Volume size for output files (100m, etc)")
parser.add_string_argument(args = ("-t", "--file_types"), default = "", description = "List of file types (comma delimited)")
parser.add_boolean_argument(args = ("-d", "--delete_originals"), description = "Delete original files")
parser.add_common_arguments()
args, unknown = parser.parse_known_args()

# Main
def main():

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
            "File types: %s" % args.file_types,
            "Delete originals: %s" % args.delete_originals
        ]
        if not prompts.prompt_for_preview("Compress files", details):
            logger.log_warning("Operation cancelled by user")
            return

    # Compress files
    for obj in paths.get_directory_contents(input_path):
        obj_path = paths.join_paths(input_path, obj)
        if not paths.is_path_file(obj_path):
            continue

        # Check file type
        should_compress = False
        for file_type in args.file_types.split(","):
            if obj_path.endswith(file_type):
                should_compress = True
        if not should_compress:
            continue

        # Get output file
        output_basename = paths.get_filename_basename(obj_path)
        output_ext = args.archive_type.cval()
        output_file = paths.join_paths(input_path, output_basename + output_ext)
        if os.path.exists(output_file):
            continue

        # Compress file
        archive.create_archive_from_file(
            archive_file = output_file,
            source_file = obj_path,
            password = args.password,
            volume_size = args.volume_size,
            delete_original = args.delete_originals,
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure)

# Start
if __name__ == "__main__":
    system.run_main(main)
