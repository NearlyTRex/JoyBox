#!/usr/bin/env python3

# Imports
import os, os.path
import sys

# Custom imports
shared_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "..", "Shared"))
sys.path.append(shared_folder)
import joybox.config as config
import joybox.system as system
import joybox.iso as iso
import joybox.arguments as arguments
import joybox.archive as archive
import joybox.setup as setup
import joybox.logger as logger
import joybox.paths as paths

# Parse arguments
parser = arguments.ArgumentParser(
    description = "Extract the files from ISO images into a folder beside each image.",
    details = (
        "Finds every `.iso` file under the input path (or takes the one file given) and\n"
        "extracts it into a `<name>` folder next to it. An ISO whose `<name>` folder already\n"
        "exists is skipped.\n"
        "\n"
        "With the default `-e Iso`, 7-Zip is tried first; if it fails, xorriso extracts the\n"
        "image instead, and the extracted files are then made readable and writable by\n"
        "everyone (666 for files, 777 for folders).\n"
        "With `-e Archive`, only 7-Zip is used.\n"
        "\n"
        "There is no confirmation prompt; the tool starts straight away."),
    examples = [
        ("Extract every ISO in a folder", "isoextract -i /path/to/isos"),
        ("Extract and delete the ISOs, previewing first", "isoextract -i /path/to/isos -d -p -v"),
        ("Extract one image with 7-Zip only", "isoextract -i \"/path/to/Game (USA).iso\" -e Archive"),
    ],
    notes = [
        "7-Zip must be installed as a JoyBox tool, and xorriso (XorrISO) for the `-e Iso` fallback.",
    ],
    see_also = ["make_iso", "decompress_archives", "chdextract"],
    section = "Game ROMs & Images")
parser.add_input_path_argument(description = "An `.iso` file, or a directory searched recursively for them; must exist")
parser.add_enum_argument(
    args = ("-e", "--extract_method"),
    arg_type = config.DiscExtractType,
    default = config.DiscExtractType.ISO,
    description = "`Iso` tries 7-Zip and falls back to xorriso; `Archive` uses 7-Zip only")
parser.add_boolean_argument(args = ("-s", "--skip_existing"), description = "With `-e Archive`, keep files that already exist in the output folder instead of overwriting them")
parser.add_boolean_argument(args = ("-d", "--delete_originals"), description = "Delete each ISO after it is extracted")
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

    # Convert disc image files
    for file in paths.build_file_list_by_extensions(input_path, extensions = [".iso"]):

        # Get file info
        current_file = file
        current_dir = paths.get_filename_directory(current_file)
        current_basename = paths.get_filename_basename(current_file)

        # Check if output dir already exists
        output_dir = paths.join_paths(current_dir, current_basename)
        if paths.is_path_directory(output_dir):
            continue

        # Extract as iso
        if args.extract_method == config.DiscExtractType.ISO:
            iso.extract_iso(
                iso_file = current_file,
                extract_dir = output_dir,
                delete_original = args.delete_originals,
                verbose = args.verbose,
                pretend_run = args.pretend_run,
                exit_on_failure = args.exit_on_failure)

        # Extract as archive
        elif args.extract_method == config.DiscExtractType.ARCHIVE:
            archive.extract_archive(
                archive_file = current_file,
                extract_dir = output_dir,
                skip_existing = args.skip_existing,
                delete_original = args.delete_originals,
                verbose = args.verbose,
                pretend_run = args.pretend_run,
                exit_on_failure = args.exit_on_failure)

# Start
if __name__ == "__main__":
    system.run_main(main)
