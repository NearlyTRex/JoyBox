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

# Parse arguments
parser = arguments.ArgumentParser(description = "Sony PlayStation 3 rom tool.")
parser.add_input_path_argument()
parser.add_boolean_argument(args = ("-e", "--verify_chd"), description = "Verify PS3 chd files")
parser.add_common_arguments()
args, unknown = parser.parse_known_args()

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Get input path
    input_path = parser.get_input_path()

    # Show preview
    if not args.no_preview:
        details = [
            "Path: %s" % input_path,
            "Action: Verify CHD"
        ]
        if not system.PromptForPreview("PS3 ROM tool", details):
            system.LogWarning("Operation cancelled by user")
            return

    # Find rom files
    for file in system.BuildFileListByExtensions(input_path, extensions = [".chd"]):

        # Verify chd
        if args.verify_chd:
            playstation.VerifyPS3CHD(
                chd_file = file,
                verbose = args.verbose,
                pretend_run = args.pretend_run,
                exit_on_failure = args.exit_on_failure)

# Start
if __name__ == "__main__":
    system.RunMain(main)
