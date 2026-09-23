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
    description = "Convert, trim, untrim, extract or inspect Nintendo 3DS CIA and CCI (.3ds) files.",
    details = (
        "Finds every `.cia` and `.3ds` file under the input path (or takes the one file given)\n"
        "and applies the chosen action to each file it fits. Output is written next to the\n"
        "source file, and the source is left in place.\n"
        "\n"
        "`-a` converts each CIA to a CCI and `-b` converts each CCI to a CIA, both with\n"
        "CtrMakeRom. `-t` trims each `<name>.3ds` into `<name>.trim.3ds`, and `-u` restores each\n"
        "`<name>.trim.3ds` to its full size as `<name>.3ds`, both with 3DSRomTool working on a\n"
        "temporary copy. `-e` unpacks each CIA with CtrTool into a `<name>` folder holding the\n"
        "certificate chain, ticket and TMD (`00000000.cer`, `.tik`, `.tmd`) and the content\n"
        "files as `.app` files. `-n` prints CtrTool's description of every CIA and CCI."),
    examples = [
        ("Trim every CCI in a folder", "3ds_rom_tool -i /path/to/3ds -t"),
        ("Preview the trim without changing anything", "3ds_rom_tool -i /path/to/3ds -t -p -v"),
        ("Restore trimmed CCIs to full size", "3ds_rom_tool -i /path/to/3ds -u"),
        ("Convert a CIA to a CCI", "3ds_rom_tool -i \"/path/to/Game (USA).cia\" -a"),
        ("Unpack every CIA into a folder of its own", "3ds_rom_tool -i /path/to/3ds -e --no-preview"),
        ("Print the header information of every 3DS file", "3ds_rom_tool -i /path/to/3ds -n"),
    ],
    notes = [
        "Give one action. When several are given, each file gets the first one in the order `-a`, `-b`, `-t`, `-u`, `-e`, `-n` that fits its type.",
        "Files already named `.trim.3ds` are not trimmed again by `-t`.",
        "CtrMakeRom, 3DSRomTool and CtrTool must be installed as JoyBox tools.",
    ],
    see_also = ["nds_rom_tool"],
    section = "Game ROMs & Images")
parser.add_input_path_argument(description = "A `.cia` or `.3ds` file, or a directory searched recursively for them; must exist")
parser.add_group("Actions")
parser.add_boolean_argument(args = ("-a", "--cia_to_cci"), description = "Convert each CIA to a CCI written next to it")
parser.add_boolean_argument(args = ("-b", "--cci_to_cia"), description = "Convert each `<name>.3ds` CCI to `<name>.cia`")
parser.add_boolean_argument(args = ("-t", "--trim_cci"), description = "Trim each `<name>.3ds` CCI into `<name>.trim.3ds`")
parser.add_boolean_argument(args = ("-u", "--untrim_cci"), description = "Restore each `<name>.trim.3ds` to full size as `<name>.3ds`")
parser.add_boolean_argument(args = ("-e", "--extract_cia"), description = "Unpack each `<name>.cia` into a `<name>` folder next to it")
parser.add_boolean_argument(args = ("-n", "--info"), description = "Print CtrTool's information for every CIA and CCI")
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
    if args.cia_to_cci:
        action = "Convert CIA to 3DS(CCI)"
    elif args.cci_to_cia:
        action = "Convert 3DS(CCI) to CIA"
    elif args.trim_cci:
        action = "Trim 3DS(CCI)"
    elif args.untrim_cci:
        action = "Untrim 3DS(CCI)"
    elif args.extract_cia:
        action = "Extract CIA"
    elif args.info:
        action = "Print info"

    # Show preview
    if not args.no_preview:
        details = [
            "Path: %s" % input_path,
            "Action: %s" % action
        ]
        if not prompts.prompt_for_preview("3DS ROM tool", details):
            logger.log_warning("Operation cancelled by user")
            return

    # Find rom files
    for file in paths.build_file_list_by_extensions(input_path, extensions = [".cia", ".3ds"]):
        current_file = file
        current_file_dir = paths.get_filename_directory(current_file)
        current_file_basename = paths.get_filename_basename(current_file).replace(".trim", "")
        current_file_ext = paths.get_filename_extension(current_file)
        output_file_cia = paths.join_paths(current_file_dir, current_file_basename + ".cia")
        output_file_3ds = paths.join_paths(current_file_dir, current_file_basename + ".3ds")
        output_file_trimmed_3ds = paths.join_paths(current_file_dir, current_file_basename + ".trim.3ds")
        output_dir = paths.join_paths(current_file_dir, current_file_basename)

        # Convert CIA to 3DS(CCI)
        if args.cia_to_cci and current_file.endswith(".cia"):
            nintendo.convert_3ds_cia_to_cci(
                src_3ds_file = current_file,
                dest_3ds_file = output_file_trimmed_3ds,
                verbose = args.verbose,
                pretend_run = args.pretend_run,
                exit_on_failure = args.exit_on_failure)

        # Convert 3DS(CCI) to CIA
        elif args.cci_to_cia and current_file.endswith(".3ds"):
            nintendo.convert_3ds_cci_to_cia(
                src_3ds_file = current_file,
                dest_3ds_file = output_file_cia,
                verbose = args.verbose,
                pretend_run = args.pretend_run,
                exit_on_failure = args.exit_on_failure)

        # Trim 3DS
        elif args.trim_cci and current_file.endswith(".3ds") and not ".trim" in current_file:
            nintendo.trim_3ds_cci(
                src_3ds_file = current_file,
                dest_3ds_file = output_file_trimmed_3ds,
                verbose = args.verbose,
                pretend_run = args.pretend_run,
                exit_on_failure = args.exit_on_failure)

        # Untrim 3DS
        elif args.untrim_cci and current_file.endswith(".trim.3ds"):
            nintendo.untrim_3ds_cci(
                src_3ds_file = current_file,
                dest_3ds_file = output_file_3ds,
                verbose = args.verbose,
                pretend_run = args.pretend_run,
                exit_on_failure = args.exit_on_failure)

        # Extract CIA
        elif args.extract_cia and current_file.endswith(".cia"):
            nintendo.extract_3ds_cia(
                src_3ds_file = current_file,
                extract_dir = output_dir,
                verbose = args.verbose,
                pretend_run = args.pretend_run,
                exit_on_failure = args.exit_on_failure)

        # Print info
        elif args.info:
            info = nintendo.get_3ds_file_info(
                src_3ds_file = current_file,
                verbose = args.verbose,
                pretend_run = args.pretend_run,
                exit_on_failure = args.exit_on_failure)
            logger.log_info(info)

# Start
if __name__ == "__main__":
    system.run_main(main)
