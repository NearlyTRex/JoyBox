#!/usr/bin/env python3

# Imports
import os, os.path
import sys

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.append(lib_folder)
import system
import nintendo
import arguments
import setup
import logger
import paths
import prompts

# Parse arguments
parser = arguments.ArgumentParser(description = "Nintendo 3DS rom tool.")
parser.add_input_path_argument()
parser.add_boolean_argument(args = ("-a", "--cia_to_cci"), description = "Convert CIA to 3DS(CCI)")
parser.add_boolean_argument(args = ("-b", "--cci_to_cia"), description = "Convert 3DS(CCI) to CIA")
parser.add_boolean_argument(args = ("-t", "--trim_cci"), description = "Trim 3DS(CCI) files")
parser.add_boolean_argument(args = ("-u", "--untrim_cci"), description = "Untrim 3DS(CCI) files")
parser.add_boolean_argument(args = ("-e", "--extract_cia"), description = "Extract CIA files")
parser.add_boolean_argument(args = ("-n", "--info"), description = "Print info for all 3DS files")
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
            nintendo.Convert3DSCIAtoCCI(
                src_3ds_file = current_file,
                dest_3ds_file = output_file_trimmed_3ds,
                verbose = args.verbose,
                pretend_run = args.pretend_run,
                exit_on_failure = args.exit_on_failure)

        # Convert 3DS(CCI) to CIA
        elif args.cci_to_cia and current_file.endswith(".3ds"):
            nintendo.Convert3DSCCItoCIA(
                src_3ds_file = current_file,
                dest_3ds_file = output_file_cia,
                verbose = args.verbose,
                pretend_run = args.pretend_run,
                exit_on_failure = args.exit_on_failure)

        # Trim 3DS
        elif args.trim_cci and current_file.endswith(".3ds") and not ".trim" in current_file:
            nintendo.Trim3DSCCI(
                src_3ds_file = current_file,
                dest_3ds_file = output_file_trimmed_3ds,
                verbose = args.verbose,
                pretend_run = args.pretend_run,
                exit_on_failure = args.exit_on_failure)

        # Untrim 3DS
        elif args.untrim_cci and current_file.endswith(".trim.3ds"):
            nintendo.Untrim3DSCCI(
                src_3ds_file = current_file,
                dest_3ds_file = output_file_3ds,
                verbose = args.verbose,
                pretend_run = args.pretend_run,
                exit_on_failure = args.exit_on_failure)

        # Extract CIA
        elif args.extract_cia and current_file.endswith(".cia"):
            nintendo.Extract3DSCIA(
                src_3ds_file = current_file,
                extract_dir = output_dir,
                verbose = args.verbose,
                pretend_run = args.pretend_run,
                exit_on_failure = args.exit_on_failure)

        # Print info
        elif args.info:
            info = nintendo.Get3DSFileInfo(
                src_3ds_file = current_file,
                verbose = args.verbose,
                pretend_run = args.pretend_run,
                exit_on_failure = args.exit_on_failure)
            logger.log_info(info)

# Start
if __name__ == "__main__":
    system.run_main(main)
