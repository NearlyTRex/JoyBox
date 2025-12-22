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
import iso
import arguments
import setup
import logger
import paths

# Parse arguments
parser = arguments.ArgumentParser(description = "Make ISO images out of all folders or zips in a path.")
parser.add_input_path_argument()
parser.add_enum_argument(
    args = ("-t", "--disc_source_type"),
    arg_type = config.DiscSourceType,
    default = config.DiscSourceType.FOLDER,
    description = "Disc source type")
parser.add_string_argument(args = ("-n", "--volume_name"), default = "", description = "Volume name to use")
parser.add_boolean_argument(args = ("-a", "--auto_volume_name"), description = "Choose volume name based automatically")
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

    # Create iso images from folders
    if args.disc_source_type == config.DiscSourceType.FOLDER:
        for obj in paths.get_directory_contents(input_path):
            obj_path = paths.join_paths(input_path, obj)
            if not paths.is_path_directory(obj_path):
                continue

            # Check if iso already exists
            output_file = paths.join_paths(input_path, obj + config.DiscImageFileType.ISO.cval())
            if os.path.exists(output_file):
                continue

            # Get volume name
            volume_name = args.volume_name
            if args.auto_volume_name:
                volume_name = obj

            # Create iso
            iso.CreateISO(
                iso_file = output_file,
                source_dir = obj_path,
                volume_name = volume_name,
                delete_original = args.delete_originals,
                verbose = args.verbose,
                pretend_run = args.pretend_run,
                exit_on_failure = args.exit_on_failure)

    # Create iso images from zips
    elif args.disc_source_type == config.DiscSourceType.ZIP:
        for file in paths.build_file_list_by_extensions(input_path, extensions = [".zip"]):

            # Get file info
            current_file = file
            current_dir = paths.get_filename_directory(current_file)
            current_basename = paths.get_filename_basename(current_file)

            # Check if iso already exists
            output_file = paths.join_paths(current_dir, current_basename + config.DiscImageFileType.ISO.cval())
            if os.path.exists(output_file):
                continue

            # Decompress zip
            extracted_dir = paths.join_paths(current_dir, current_basename + "_extracted")
            archive.ExtractArchive(
                archive_file = current_file,
                extract_dir = extracted_dir,
                work_dir = current_dir,
                delete_original = args.delete_originals,
                verbose = args.verbose,
                pretend_run = args.pretend_run,
                exit_on_failure = args.exit_on_failure)

            # Get volume name
            volume_name = args.volume_name
            if args.auto_volume_name:
                volume_name = current_basename

            # Create iso
            iso.CreateISO(
                iso_file = output_file,
                source_dir = extracted_dir,
                work_dir = extracted_dir,
                volume_name = volume_name,
                delete_original = args.delete_originals,
                verbose = args.verbose,
                pretend_run = args.pretend_run,
                exit_on_failure = args.exit_on_failure)

# Start
if __name__ == "__main__":
    system.run_main(main)
