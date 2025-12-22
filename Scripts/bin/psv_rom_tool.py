#!/usr/bin/env python3

# Imports
import os, os.path
import sys

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.append(lib_folder)
import system
import playstation
import arguments
import setup
import logger
import paths
import prompts

# Parse arguments
parser = arguments.ArgumentParser(description = "Sony PlayStation Vita rom tool.")
parser.add_input_path_argument()
parser.add_boolean_argument(args = ("-s", "--strip"), description = "Strip PSV files")
parser.add_boolean_argument(args = ("-u", "--unstrip"), description = "Unstrip PSV files")
parser.add_boolean_argument(args = ("-t", "--trim"), description = "Trim PSV files")
parser.add_boolean_argument(args = ("-n", "--untrim"), description = "Untrim PSV files")
parser.add_boolean_argument(args = ("-e", "--verify"), description = "Verify PSV files")
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
            playstation.StripPSV(
                src_psv_file = current_file,
                dest_psv_file = paths.join_paths(current_file_dir, current_file_basename + "_stripped.psv"),
                delete_original = args.delete_originals,
                verbose = args.verbose,
                pretend_run = args.pretend_run,
                exit_on_failure = args.exit_on_failure)

        # Unstrip psv
        elif args.unstrip:
            playstation.UnstripPSV(
                src_psv_file = current_file,
                src_psve_file = paths.join_paths(current_file_dir, current_file_basename + ".psve"),
                dest_psv_file = paths.join_paths(current_file_dir, current_file_basename + "_unstripped.psv"),
                delete_original = args.delete_originals,
                verbose = args.verbose,
                pretend_run = args.pretend_run,
                exit_on_failure = args.exit_on_failure)

        # Trim psv
        elif args.trim:
            playstation.TrimPSV(
                src_psv_file = current_file,
                dest_psv_file = paths.join_paths(current_file_dir, current_file_basename + "_trimmed.psv"),
                delete_original = args.delete_originals,
                verbose = args.verbose,
                pretend_run = args.pretend_run,
                exit_on_failure = args.exit_on_failure)

        # Untrim psv
        elif args.untrim:
            playstation.UntrimPSV(
                src_psv_file = current_file,
                dest_psv_file = paths.join_paths(current_file_dir, current_file_basename + "_untrimmed.psv"),
                delete_original = args.delete_originals,
                verbose = args.verbose,
                pretend_run = args.pretend_run,
                exit_on_failure = args.exit_on_failure)

        # Verify psv
        elif args.verify:
            playstation.VerifyPSV(
                psv_file = current_file,
                verbose = args.verbose,
                pretend_run = args.pretend_run,
                exit_on_failure = args.exit_on_failure)

# Start
if __name__ == "__main__":
    system.run_main(main)
