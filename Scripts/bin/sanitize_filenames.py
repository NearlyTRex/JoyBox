#!/usr/bin/env python3

# Imports
import os
import sys

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.append(lib_folder)
import config
import system
import arguments
import setup

# Parse arguments
parser = arguments.ArgumentParser(description = "Sanitize filenames.")
parser.add_input_path_argument()
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
        details = ["Path: %s" % input_path]
        if not system.PromptForPreview("Sanitize filenames", details):
            system.LogWarning("Operation cancelled by user")
            return

    # Sanitize filenames
    system.SanitizeFilenames(
        path = input_path,
        verbose = args.verbose,
        pretend_run = args.pretend_run,
        exit_on_failure = args.exit_on_failure)

# Start
if __name__ == "__main__":
    system.RunMain(main)
