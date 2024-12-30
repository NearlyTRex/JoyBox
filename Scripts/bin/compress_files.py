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
parser = arguments.ArgumentParser(description = "Compress files.")
parser.add_input_path_argument()
parser.add_enum_argument(
    args = ("-a", "--archive_type"),
    arg_type = config.ArchiveType,
    default = config.ArchiveType.ZIP,
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
    setup.CheckRequirements()

    # Get input path
    input_path = parser.get_input_path()

    # Compress files
    for obj in system.GetDirectoryContents(input_path):
        obj_path = os.path.join(input_path, obj)
        if not system.IsPathFile(obj_path):
            continue

        # Check file type
        should_compress = False
        for file_type in args.file_types.split(","):
            if obj_path.endswith(file_type):
                should_compress = True
        if not should_compress:
            continue

        # Get output file
        output_basename = system.GetFilenameBasename(obj_path)
        output_ext = archive.GetArchiveExtension(args.archive_type)
        output_file = os.path.join(input_path, output_basename + "." + output_ext)
        if os.path.exists(output_file):
            continue

        # Compress file
        archive.CreateArchiveFromFile(
            archive_file = output_file,
            source_file = obj_path,
            password = args.password,
            volume_size = args.volume_size,
            delete_original = args.delete_originals,
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure)

# Start
main()
