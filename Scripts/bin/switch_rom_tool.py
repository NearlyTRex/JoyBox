#!/usr/bin/env python3

# Imports
import os, os.path
import sys

# Custom imports
shared_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "..", "Shared"))
sys.path.append(shared_folder)
import joybox.system as system
import joybox.nintendo as nintendo
import joybox.arguments as arguments
import joybox.setup as setup
import joybox.logger as logger
import joybox.paths as paths
import joybox.prompts as prompts

# Parse arguments
parser = arguments.ArgumentParser(
    description = "Trim or untrim Nintendo Switch cartridge images (.xci).",
    details = (
        "Finds every `.xci` file under the input path (or takes the one file given) and runs\n"
        "XCI Trimmer on a temporary copy of it. `-t` removes the unused padding at the end of\n"
        "the image and writes `<name>_trimmed.xci`; `-u` pads a trimmed image back to its full\n"
        "cartridge size and writes `<name>_untrimmed.xci`. Both are written next to the source.\n"
        "\n"
        "With `-d` the source `.xci` is deleted after XCI Trimmer succeeds and the new file\n"
        "has been moved into place."),
    examples = [
        ("Trim every XCI in a folder", "switch_rom_tool -i /path/to/switch -t"),
        ("Trim and delete the originals, previewing first", "switch_rom_tool -i /path/to/switch -t -d -p -v"),
        ("Pad one trimmed image back to full size", "switch_rom_tool -i \"/path/to/Game (USA).xci\" -u"),
    ],
    notes = [
        "Without `-t` or `-u` nothing is done. If both are given, `-t` wins.",
        "Output files are also `.xci`, so running the tool again on the same folder processes them too.",
        "Each image is copied to the temporary directory first, which needs room for the image and its output.",
        "XCI Trimmer and the JoyBox Python environment must be installed as JoyBox tools.",
    ],
    see_also = ["3ds_rom_tool"],
    section = "Game ROMs & Images")
parser.add_input_path_argument(description = "An `.xci` file, or a directory searched recursively for them; must exist")
parser.add_boolean_argument(args = ("-t", "--trim"), description = "Trim each image into `<name>_trimmed.xci`")
parser.add_boolean_argument(args = ("-u", "--untrim"), description = "Pad each image to full size into `<name>_untrimmed.xci`")
parser.add_boolean_argument(args = ("-d", "--delete_originals"), description = "Delete the source `.xci` after it is trimmed or untrimmed")
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

    # Determine action
    action = "Trim" if args.trim else "Untrim" if args.untrim else None

    # Show preview
    if not args.no_preview:
        details = [
            "Path: %s" % input_path,
            "Action: %s" % action,
            "Delete originals: %s" % args.delete_originals
        ]
        if not prompts.prompt_for_preview("Switch ROM tool", details):
            logger.log_warning("Operation cancelled by user")
            return

    # Find xci files
    for file in paths.build_file_list_by_extensions(input_path, extensions = [".xci"]):
        current_file = file
        current_file_dir = paths.get_filename_directory(current_file)
        current_file_basename = paths.get_filename_basename(current_file)

        # Trim xci
        if args.trim:
            nintendo.trim_switch_xci(
                src_xci_file = current_file,
                dest_xci_file = paths.join_paths(current_file_dir, current_file_basename + "_trimmed.xci"),
                delete_original = args.delete_originals,
                verbose = args.verbose,
                pretend_run = args.pretend_run,
                exit_on_failure = args.exit_on_failure)

        # Untrim xci
        elif args.untrim:
            nintendo.untrim_switch_xci(
                src_xci_file = current_file,
                dest_xci_file = paths.join_paths(current_file_dir, current_file_basename + "_untrimmed.xci"),
                delete_original = args.delete_originals,
                verbose = args.verbose,
                pretend_run = args.pretend_run,
                exit_on_failure = args.exit_on_failure)

# Start
if __name__ == "__main__":
    system.run_main(main)
