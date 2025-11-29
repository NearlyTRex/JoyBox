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

# Parse arguments
parser = arguments.ArgumentParser(description = "Nintendo Switch rom tool.")
parser.add_input_path_argument()
parser.add_boolean_argument(args = ("-t", "--trim"), description = "Trim XCI files")
parser.add_boolean_argument(args = ("-u", "--untrim"), description = "Untrim XCI files")
parser.add_boolean_argument(args = ("-d", "--delete_originals"), description = "Delete original files")
parser.add_common_arguments()
args, unknown = parser.parse_known_args()

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

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
        if not system.PromptForPreview("Switch ROM tool", details):
            system.LogWarning("Operation cancelled by user")
            return

    # Find xci files
    for file in system.BuildFileListByExtensions(input_path, extensions = [".xci"]):
        current_file = file
        current_file_dir = system.GetFilenameDirectory(current_file)
        current_file_basename = system.GetFilenameBasename(current_file)

        # Trim xci
        if args.trim:
            nintendo.TrimSwitchXCI(
                src_xci_file = current_file,
                dest_xci_file = system.JoinPaths(current_file_dir, current_file_basename + "_trimmed.xci"),
                delete_original = args.delete_originals,
                verbose = args.verbose,
                pretend_run = args.pretend_run,
                exit_on_failure = args.exit_on_failure)

        # Untrim xci
        elif args.untrim:
            nintendo.UntrimSwitchXCI(
                src_xci_file = current_file,
                dest_xci_file = system.JoinPaths(current_file_dir, current_file_basename + "_untrimmed.xci"),
                delete_original = args.delete_originals,
                verbose = args.verbose,
                pretend_run = args.pretend_run,
                exit_on_failure = args.exit_on_failure)

# Start
if __name__ == "__main__":
    system.RunMain(main)
