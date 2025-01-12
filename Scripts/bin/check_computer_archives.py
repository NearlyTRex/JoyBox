#!/usr/bin/env python3

# Imports
import os, os.path
import sys

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.append(lib_folder)
import system
import arguments
import setup

# Parse arguments
parser = arguments.ArgumentParser(description = "Check computer archives.")
parser.add_input_path_argument()
parser.add_common_arguments()
args, unknown = parser.parse_known_args()

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Get input path
    input_path = parser.get_input_path()

    # Check computer archives
    for file in system.BuildFileListByExtensions(input_path, extensions = [".exe"]):

        # Check exe size
        system.LogInfo("Checking exe file %s ..." % file)
        exe_filesize = os.path.getsize(file)
        if exe_filesize > 4290772992:
            system.LogError("Executable '%s' is larger than 4092 MB" % file, quit_program = True)

# Start
main()
