#!/usr/bin/env python3

# Imports
import os, os.path
import sys

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.append(lib_folder)
import config
import system
import chd
import arguments
import setup
import logger

# Parse arguments
parser = arguments.ArgumentParser(description = "Convert disc images to CHD files.")
parser.add_input_path_argument()
parser.add_enum_argument(
    args = ("-t", "--disc_image_types"),
    arg_type = config.DiscImageFileType,
    default = [config.DiscImageFileType.ISO, config.DiscImageFileType.CUE, config.DiscImageFileType.GDI],
    description = "Disc image types",
    allow_multiple = True)
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
            "Disc image types: %s" % [t.cval() for t in args.disc_image_types],
            "Delete originals: %s" % args.delete_originals
        ]
        if not system.PromptForPreview("Convert to CHD", details):
            logger.log_warning("Operation cancelled by user")
            return

    # Convert disc image files
    disc_image_extensions = [disc_image_type.cval() for disc_image_type in args.disc_image_types]
    for file in system.BuildFileListByExtensions(input_path, extensions = disc_image_extensions):

        # Get file info
        current_file = file
        current_dir = system.GetFilenameDirectory(current_file)
        current_basename = system.GetFilenameBasename(current_file)

        # Check if output already exists
        output_chd = system.JoinPaths(current_dir, current_basename + config.DiscImageFileType.CHD.cval())
        if os.path.exists(output_chd):
            continue

        # Create disc chd
        chd.CreateDiscCHD(
            chd_file = output_chd,
            source_iso = current_file,
            delete_original = args.delete_originals,
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure)

# Start
if __name__ == "__main__":
    system.RunMain(main)
