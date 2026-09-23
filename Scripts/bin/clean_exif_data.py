#!/usr/bin/env python3

# Imports
import os, os.path
import sys

# Custom imports
shared_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "..", "Shared"))
sys.path.append(shared_folder)
import joybox.command as command
import joybox.system as system
import joybox.programs as programs
import joybox.asset as asset
import joybox.arguments as arguments
import joybox.setup as setup
import joybox.logger as logger

# Parse arguments
parser = arguments.ArgumentParser(
    description = "Strip all EXIF and other embedded metadata from image files.",
    details = (
        "Runs ExifTool with `-All=` over the input, removing every writable metadata tag\n"
        "(camera, GPS location, timestamps, thumbnails and so on). A directory is processed\n"
        "recursively. Files are rewritten in place with `-overwrite_original`, so no backup\n"
        "copies are left behind."),
    examples = [
        ("Strip metadata from one photo", "clean_exif_data -i ~/Pictures/photo.jpg"),
        ("Strip metadata from every file in a directory tree", "clean_exif_data -i ~/Pictures/ToShare"),
        ("Dry run, leaving every file untouched", "clean_exif_data -i ~/Pictures/ToShare -p -v"),
    ],
    notes = [
        "The change cannot be undone; copy anything whose metadata you want to keep first.",
        "ExifTool must be installed with `setup_tools -k ExifTool`.",
    ],
    see_also = ["setup_tools"],
    section = "Files & Archives")
parser.add_input_path_argument(description = "Image file, or directory to process recursively; it must exist")
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

    # Clean exif data
    asset.clean_exif_data(
        asset_file = input_path,
        verbose = args.verbose,
        pretend_run = args.pretend_run,
        exit_on_failure = args.exit_on_failure)

# Start
if __name__ == "__main__":
    system.run_main(main)
