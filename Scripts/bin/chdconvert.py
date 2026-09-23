#!/usr/bin/env python3

# Imports
import os, os.path
import sys

# Custom imports
shared_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "..", "Shared"))
sys.path.append(shared_folder)
import joybox.config as config
import joybox.system as system
import joybox.chd as chd
import joybox.arguments as arguments
import joybox.setup as setup
import joybox.logger as logger
import joybox.paths as paths
import joybox.prompts as prompts

# Parse arguments
parser = arguments.ArgumentParser(
    description = "Convert CD disc images (ISO, CUE, GDI) to CHD files with chdman.",
    details = (
        "Finds every disc image of the chosen types under the input path (or takes the one\n"
        "file given) and runs `chdman createcd` on it, writing `<name>.chd` next to it. For a\n"
        "`.cue` or `.gdi` sheet, chdman reads the track files the sheet lists.\n"
        "\n"
        "An image whose `<name>.chd` already exists is skipped."),
    examples = [
        ("Convert every ISO, CUE and GDI image in a folder", "chdconvert -i /path/to/discs"),
        ("Convert only CUE sheets and delete them afterwards, previewing first", "chdconvert -i /path/to/discs -t CUE -d -p -v"),
        ("Convert ISO and GDI images only", "chdconvert -i /path/to/discs -t ISO GDI"),
    ],
    notes = [
        "Images are always converted with `createcd`, which makes CD CHDs.",
        "chdman (MameChdman) must be installed as a JoyBox tool.",
    ],
    see_also = ["chdextract", "chdverify", "chdzip"],
    section = "Game ROMs & Images")
parser.add_input_path_argument(description = "A disc image file, or a directory searched recursively for images; must exist")
parser.add_enum_argument(
    args = ("-t", "--disc_image_types"),
    arg_type = config.DiscImageFileType,
    default = [config.DiscImageFileType.ISO, config.DiscImageFileType.CUE, config.DiscImageFileType.GDI],
    description = "Image types to convert, space separated; each selects files by its extension (`ISO` is `.iso`, `CUE` is `.cue`, and so on)",
    allow_multiple = True)
parser.add_boolean_argument(args = ("-d", "--delete_originals"), description = "Delete the image file given to chdman (the `.iso`, `.cue`, `.gdi` or `.toc` itself) once its CHD is made")
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
            "Disc image types: %s" % [t.cval() for t in args.disc_image_types],
            "Delete originals: %s" % args.delete_originals
        ]
        if not prompts.prompt_for_preview("Convert to CHD", details):
            logger.log_warning("Operation cancelled by user")
            return

    # Convert disc image files
    disc_image_extensions = [disc_image_type.cval() for disc_image_type in args.disc_image_types]
    for file in paths.build_file_list_by_extensions(input_path, extensions = disc_image_extensions):

        # Get file info
        current_file = file
        current_dir = paths.get_filename_directory(current_file)
        current_basename = paths.get_filename_basename(current_file)

        # Check if output already exists
        output_chd = paths.join_paths(current_dir, current_basename + config.DiscImageFileType.CHD.cval())
        if os.path.exists(output_chd):
            continue

        # Create disc chd
        chd.create_disc_chd(
            chd_file = output_chd,
            source_iso = current_file,
            delete_original = args.delete_originals,
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure)

# Start
if __name__ == "__main__":
    system.run_main(main)
