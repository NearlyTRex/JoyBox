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
parser = arguments.ArgumentParser(description = "Nintendo DS rom tool.")
parser.add_input_path_argument()
parser.add_boolean_argument(args = ("-d", "--decrypt"), description = "Decrypt NDS files")
parser.add_boolean_argument(args = ("-e", "--encrypt"), description = "Verify NDS files")
parser.add_boolean_argument(args = ("-g", "--generate_hash"), description = "Output size and hashes to a companion file")
parser.add_common_arguments()
args, unknown = parser.parse_known_args()

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Get input path
    input_path = parser.get_input_path()

    # Find rom files
    for file in system.BuildFileListByExtensions(input_path, extensions = [".nds"]):
        current_file = file
        current_file_dir = system.GetFilenameDirectory(current_file)
        current_file_basename = system.GetFilenameBasename(current_file)

        # Decrypt NDS file
        if args.decrypt:
            nintendo.DecryptNDSRom(
                nds_file = current_file,
                generate_hash = args.generate_hash,
                verbose = args.verbose,
                pretend_run = args.pretend_run,
                exit_on_failure = args.exit_on_failure)

        # Encrypt NDS file
        elif args.encrypt:
            nintendo.EncryptNDSRom(
                nds_file = current_file,
                generate_hash = args.generate_hash,
                verbose = args.verbose,
                pretend_run = args.pretend_run,
                exit_on_failure = args.exit_on_failure)

# Start
main()
