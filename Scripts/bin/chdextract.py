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
    description = "Extract CD disc images from CHD files with chdman.",
    details = (
        "Finds every `.chd` file under the input path (or takes the one file given) and runs\n"
        "`chdman extractcd` on it, writing a table of contents `<name>.cue` and the track\n"
        "data `<name>.bin` next to it. `-t` and `-b` change those two extensions; chdman\n"
        "picks the table-of-contents format from the extension, so `-t .gdi` writes a GDI\n"
        "sheet and `-t .toc` a cdrdao TOC.\n"
        "\n"
        "A CHD is skipped when either output file already exists."),
    examples = [
        ("Extract every CHD in a folder to CUE/BIN", "chdextract -i /path/to/chds"),
        ("Extract to CUE/BIN and delete the CHDs, previewing first", "chdextract -i /path/to/chds -d -p -v"),
        ("Extract a Dreamcast CHD with a GDI sheet", "chdextract -i \"/path/to/Game (USA).chd\" -t .gdi"),
    ],
    notes = [
        "chdman (MameChdman) must be installed as a JoyBox tool.",
    ],
    see_also = ["chdconvert", "chdverify", "chdzip", "isoextract"],
    section = "Game ROMs & Images")
parser.add_input_path_argument(description = "A `.chd` file, or a directory searched recursively for them; must exist")
parser.add_string_argument(args = ("-t", "--toc_ext"), default = ".cue", description = "Extension of the table-of-contents file, including the dot; chdman writes CUE, GDI or TOC format to match")
parser.add_string_argument(args = ("-b", "--bin_ext"), default = ".bin", description = "Extension of the binary track file, including the dot")
parser.add_boolean_argument(args = ("-d", "--delete_originals"), description = "Delete each CHD after it is extracted")
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
            "Output: %s + %s" % (args.toc_ext, args.bin_ext),
            "Delete originals: %s" % args.delete_originals
        ]
        if not prompts.prompt_for_preview("Extract CHD", details):
            logger.log_warning("Operation cancelled by user")
            return

    # Convert disc image files
    for file in paths.build_file_list_by_extensions(input_path, extensions = [".chd"]):

        # Get file info
        current_file = file
        current_dir = paths.get_filename_directory(current_file)
        current_basename = paths.get_filename_basename(current_file)

        # Check if output already exists
        output_bin = paths.join_paths(current_dir, current_basename + args.bin_ext)
        output_toc = paths.join_paths(current_dir, current_basename + args.toc_ext)
        if os.path.exists(output_bin) or os.path.exists(output_toc):
            continue

        # Extract disc chd
        chd.extract_disc_chd(
            chd_file = current_file,
            binary_file = output_bin,
            toc_file = output_toc,
            delete_original = args.delete_originals,
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure)

# Start
if __name__ == "__main__":
    system.run_main(main)
