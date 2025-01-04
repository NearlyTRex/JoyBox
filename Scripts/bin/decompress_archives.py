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

    # Get input path
    input_path = parser.get_input_path()

    # Decompress archives
    archive_extensions = [archive_type.cval() for archive_type in args.archive_types]
    for file in system.BuildFileListByExtensions(input_path, extensions = archive_extensions):

        # Get file info
        current_file = file
        file_dir = system.GetFilenameDirectory(current_file)
        file_basename = system.GetFilenameBasename(current_file)
        output_dir = os.path.join(file_dir, file_basename)
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
main()
