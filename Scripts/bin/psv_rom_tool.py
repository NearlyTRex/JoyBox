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
    description = "Strip, unstrip, trim, untrim or verify PlayStation Vita cartridge dumps (.psv).",
    details = (
        "Finds every `.psv` file under the input path (or takes the one file given) and applies\n"
        "one action to each. New files are written next to the source:\n"
        "\n"
        "- `-s` strips the dump with PSVStrip into `<name>_stripped.psv`.\n"
        "- `-u` rebuilds a full dump from a stripped one and the `<name>.psve` file next to it\n"
        "  with PSVStrip, into `<name>_unstripped.psv`.\n"
        "- `-t` trims the unused space with PSVTools into `<name>_trimmed.psv`.\n"
        "- `-n` expands a trimmed dump back to full size with PSVTools into\n"
        "  `<name>_untrimmed.psv`.\n"
        "- `-e` runs the PSVTools check on each dump and writes nothing.\n"
        "\n"
        "With `-d` the source `.psv` is deleted after each successful strip, unstrip, trim or\n"
        "untrim."),
    examples = [
        ("Verify every dump in a folder", "psv_rom_tool -i /path/to/psv -e"),
        ("Trim every dump and delete the untrimmed originals", "psv_rom_tool -i /path/to/psv -t -d"),
        ("Preview the trim without changing anything", "psv_rom_tool -i /path/to/psv -t -d -p -v"),
        ("Rebuild a full dump from a stripped one and its .psve", "psv_rom_tool -i \"/path/to/Game (USA).psv\" -u"),
    ],
    notes = [
        "Give one action. When several are given, only the first in the order `-s`, `-u`, `-t`, `-n`, `-e` is used.",
        "Output files are also `.psv`, so running the tool again on the same folder processes them too.",
        "PSVStrip, and PSVTools with the JoyBox Python environment, must be installed as JoyBox tools.",
    ],
    see_also = ["psn_rom_tool"],
    section = "Game ROMs & Images")
parser.add_input_path_argument(description = "A `.psv` file, or a directory searched recursively for them; must exist")
parser.add_group("Actions")
parser.add_boolean_argument(args = ("-s", "--strip"), description = "Strip each dump into `<name>_stripped.psv`")
parser.add_boolean_argument(args = ("-u", "--unstrip"), description = "Rebuild each stripped dump from it and `<name>.psve` into `<name>_unstripped.psv`")
parser.add_boolean_argument(args = ("-t", "--trim"), description = "Trim each dump into `<name>_trimmed.psv`")
parser.add_boolean_argument(args = ("-n", "--untrim"), description = "Expand each trimmed dump to full size into `<name>_untrimmed.psv`")
parser.add_boolean_argument(args = ("-e", "--verify"), description = "Check each dump with PSVTools without writing anything")
parser.add_group("Behavior")
parser.add_boolean_argument(args = ("-d", "--delete_originals"), description = "Delete the source `.psv` after it is converted; ignored by `-e`")
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
    action = None
    if args.strip:
        action = "Strip"
    elif args.unstrip:
        action = "Unstrip"
    elif args.trim:
        action = "Trim"
    elif args.untrim:
        action = "Untrim"
    elif args.verify:
        action = "Verify"

    # Show preview
    if not args.no_preview:
        details = [
            "Path: %s" % input_path,
            "Action: %s" % action
        ]
        if args.delete_originals:
            details.append("Delete originals: %s" % args.delete_originals)
        if not prompts.prompt_for_preview("PSV ROM tool", details):
            logger.log_warning("Operation cancelled by user")
            return

    # Find psv files
    for file in paths.build_file_list_by_extensions(input_path, extensions = [".psv"]):
        current_file = file
        current_file_dir = paths.get_filename_directory(current_file)
        current_file_basename = paths.get_filename_basename(current_file)

        # Strip psv
        if args.strip:
            playstation.strip_psv(
                src_psv_file = current_file,
                dest_psv_file = paths.join_paths(current_file_dir, current_file_basename + "_stripped.psv"),
                delete_original = args.delete_originals,
                verbose = args.verbose,
                pretend_run = args.pretend_run,
                exit_on_failure = args.exit_on_failure)

        # Unstrip psv
        elif args.unstrip:
            playstation.unstrip_psv(
                src_psv_file = current_file,
                src_psve_file = paths.join_paths(current_file_dir, current_file_basename + ".psve"),
                dest_psv_file = paths.join_paths(current_file_dir, current_file_basename + "_unstripped.psv"),
                delete_original = args.delete_originals,
                verbose = args.verbose,
                pretend_run = args.pretend_run,
                exit_on_failure = args.exit_on_failure)

        # Trim psv
        elif args.trim:
            playstation.trim_psv(
                src_psv_file = current_file,
                dest_psv_file = paths.join_paths(current_file_dir, current_file_basename + "_trimmed.psv"),
                delete_original = args.delete_originals,
                verbose = args.verbose,
                pretend_run = args.pretend_run,
                exit_on_failure = args.exit_on_failure)

        # Untrim psv
        elif args.untrim:
            playstation.untrim_psv(
                src_psv_file = current_file,
                dest_psv_file = paths.join_paths(current_file_dir, current_file_basename + "_untrimmed.psv"),
                delete_original = args.delete_originals,
                verbose = args.verbose,
                pretend_run = args.pretend_run,
                exit_on_failure = args.exit_on_failure)

        # Verify psv
        elif args.verify:
            playstation.verify_psv(
                psv_file = current_file,
                verbose = args.verbose,
                pretend_run = args.pretend_run,
                exit_on_failure = args.exit_on_failure)

# Start
if __name__ == "__main__":
    system.run_main(main)
