#!/usr/bin/env python3

# Imports
import os, os.path
import sys

# Custom imports
shared_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "..", "Shared"))
sys.path.append(shared_folder)
import joybox.system as system
import joybox.playstation as playstation
import joybox.arguments as arguments
import joybox.setup as setup
import joybox.logger as logger
import joybox.paths as paths
import joybox.prompts as prompts

# Parse arguments
parser = arguments.ArgumentParser(
    description = "Rename PlayStation Network packages and license files to their content IDs.",
    details = (
        "With `-r`, every PSN file under the input path is renamed in its own directory to the\n"
        "36-character content ID it belongs to, such as\n"
        "`UP0001-NPUB12345_00-GAMENAME00000001`:\n"
        "\n"
        "- `.rap` files take the content ID from the `.pkg` file with the same base name next to\n"
        "  them, so they are renamed before the packages are. A `.rap` without a matching\n"
        "  `.pkg` is left alone.\n"
        "- `.pkg` files take it from the package header.\n"
        "- `.work.bin` and `.fake.rif` license files take it from their own contents.\n"
        "\n"
        "Extensions are kept, so the results are `<content id>.rap`, `.pkg`, `.work.bin` and\n"
        "`.fake.rif`."),
    examples = [
        ("Rename the PSN files in a folder", "psn_rom_tool -i /path/to/psn -r"),
        ("Preview the renames without changing anything", "psn_rom_tool -i /path/to/psn -r -p -v"),
    ],
    notes = [
        "A file whose new name is already taken is left as it is.",
        "Without `-r` nothing is done.",
    ],
    see_also = ["ps3_rom_tool", "psv_rom_tool"],
    section = "Game ROMs & Images")
parser.add_input_path_argument(description = "A PSN file, or a directory searched recursively for `.pkg`, `.rap`, `.work.bin` and `.fake.rif` files; must exist")
parser.add_boolean_argument(args = ("-r", "--rename"), description = "Rename each file to `<content id>` plus its original extension")
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
            "Action: Rename PSN files"
        ]
        if not prompts.prompt_for_preview("PSN ROM tool", details):
            logger.log_warning("Operation cancelled by user")
            return

    # Rename psn files
    if args.rename:
        for rap_file in paths.build_file_list_by_extensions(input_path, extensions = [".rap"]):
            playstation.rename_psn_rap_file(
                rap_file = rap_file,
                verbose = args.verbose,
                pretend_run = args.pretend_run,
                exit_on_failure = args.exit_on_failure)
        for pkg_file in paths.build_file_list_by_extensions(input_path, extensions = [".pkg"]):
            playstation.rename_psn_package_file(
                pkg_file = pkg_file,
                verbose = args.verbose,
                pretend_run = args.pretend_run,
                exit_on_failure = args.exit_on_failure)
        for bin_file in paths.build_file_list_by_extensions(input_path, extensions = [".bin"]):
            if bin_file.endswith(".work.bin"):
                playstation.rename_psn_workbin_file(
                    workbin_file = bin_file,
                    verbose = args.verbose,
                    pretend_run = args.pretend_run,
                    exit_on_failure = args.exit_on_failure)
        for rif_file in paths.build_file_list_by_extensions(input_path, extensions = [".rif"]):
            if rif_file.endswith(".fake.rif"):
                playstation.rename_psn_fakerif_file(
                    fakerif_file = rif_file,
                    verbose = args.verbose,
                    pretend_run = args.pretend_run,
                    exit_on_failure = args.exit_on_failure)

# Start
if __name__ == "__main__":
    system.run_main(main)
