#!/usr/bin/env python3

# Imports
import os, os.path
import sys

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.append(lib_folder)
import config
import system
import setup
import iso
import arguments
import archive

# Parse arguments
parser = arguments.ArgumentParser(description = "Extract data from ISO files.")
parser.add_input_path_argument()
parser.add_enum_argument(
    args = ("-e", "--extract_method"),
    arg_type = config.DiscExtractType,
    default = config.DiscExtractType.ISO,
    description = "Disc extract type")
parser.add_boolean_argument(args = ("-s", "--skip_existing"), description = "Skip existing extracted files")
parser.add_boolean_argument(args = ("-d", "--delete_originals"), description = "Delete original files")
parser.add_common_arguments()
args, unknown = parser.parse_known_args()

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Get input path
    input_path = parser.get_input_path()

    # Convert disc image files
    for file in system.BuildFileListByExtensions(input_path, extensions = [".iso"]):

        # Get file info
        current_file = file
        current_dir = system.GetFilenameDirectory(current_file)
        current_basename = system.GetFilenameBasename(current_file)

        # Check if output dir already exists
        output_dir = system.JoinPaths(current_dir, current_basename)
        if system.IsPathDirectory(output_dir):
            continue

        # Extract as iso
        if args.extract_method == config.DiscExtractType.ISO:
            iso.ExtractISO(
                iso_file = current_file,
                extract_dir = output_dir,
                delete_original = args.delete_originals,
                verbose = args.verbose,
                pretend_run = args.pretend_run,
                exit_on_failure = args.exit_on_failure)

        # Extract as archive
        elif args.extract_method == config.DiscExtractType.ARCHIVE:
            archive.ExtractArchive(
                archive_file = current_file,
                extract_dir = output_dir,
                skip_existing = args.skip_existing,
                delete_original = args.delete_originals,
                verbose = args.verbose,
                pretend_run = args.pretend_run,
                exit_on_failure = args.exit_on_failure)

# Start
main()
