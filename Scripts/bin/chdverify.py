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

    # Convert disc image files
    for file in system.BuildFileListByExtensions(input_path, extensions = [".chd"]):

        # Verify disc chd
        system.LogInfo("Verifying %s ..." % file)
        verification_success = chd.VerifyDiscCHD(file)
        if verification_success:
            system.LogInfo("Verified!")
        else:
            system.LogErrorAndQuit("Verification failed!")

# Start
main()
