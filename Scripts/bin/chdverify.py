#!/usr/bin/env python3

# Imports
import os, os.path
import sys

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.append(lib_folder)
import config
import system
import chd
import arguments
import setup

# Parse arguments
parser = arguments.ArgumentParser(description = "Verify disc images from CHD files.")
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
        if not system.PromptForPreview("Verify CHD", details):
            system.LogWarning("Operation cancelled by user")
            return

    # Convert disc image files
    for file in system.BuildFileListByExtensions(input_path, extensions = [".chd"]):

        # Verify disc chd
        system.LogInfo("Verifying %s ..." % file)
        verification_success = chd.VerifyDiscCHD(file)
        if verification_success:
            system.LogInfo("Verified!")
        else:
            system.LogError("Verification failed!", quit_program = True)

# Start
if __name__ == "__main__":
    system.RunMain(main)
