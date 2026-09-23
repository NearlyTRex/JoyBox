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
    description = "Repack the files on each CHD disc image into a zip archive.",
    details = (
        "Finds every `.chd` file under the input path (or takes the one file given) and turns\n"
        "the filesystem on the disc into `<name>.zip` next to it. chdman extracts the disc to\n"
        "`<name>.iso` and `<name>.toc` beside the CHD, the ISO is mounted on a temporary\n"
        "directory (with fuseiso on Linux), and 7-Zip archives the mounted files.\n"
        "\n"
        "A CHD whose `<name>.zip` already exists is skipped."),
    examples = [
        ("Zip the contents of every CHD in a folder", "chdzip -i /path/to/chds"),
        ("Zip and delete the CHDs, previewing first", "chdzip -i /path/to/chds -d -p -v"),
    ],
    notes = [
        "Only the files in the disc's filesystem go into the zip, not the disc image itself.",
        "The extracted ISO sits next to the CHD, so that directory needs room for a full copy of the disc.",
        "chdman (MameChdman) and 7-Zip must be installed as JoyBox tools, and on Linux fuseiso as well.",
    ],
    see_also = ["chdextract", "isoextract", "compress_folders"],
    section = "Game ROMs & Images")
parser.add_input_path_argument(description = "A `.chd` file, or a directory searched recursively for them; must exist")
parser.add_boolean_argument(args = ("-d", "--delete_originals"), description = "Delete each CHD after its zip is written")
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
            "Delete originals: %s" % args.delete_originals
        ]
        if not prompts.prompt_for_preview("CHD to ZIP", details):
            logger.log_warning("Operation cancelled by user")
            return

    # Convert disc image files
    for file in paths.build_file_list_by_extensions(input_path, extensions = [".chd"]):

        # Get file info
        current_file = file
        current_dir = paths.get_filename_directory(current_file)
        current_basename = paths.get_filename_basename(current_file)

        # Check if output already exists
        output_zip = paths.join_paths(current_dir, current_basename + config.ArchiveFileType.ZIP.cval())
        if os.path.exists(output_zip):
            continue

        # Extract disc chd
        chd.archive_disc_chd(
            chd_file = current_file,
            zip_file = output_zip,
            delete_original = args.delete_originals,
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure)

# Start
if __name__ == "__main__":
    system.run_main(main)
