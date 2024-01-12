#!/usr/bin/env python3

# Imports
import os, os.path
import sys
import argparse

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.append(lib_folder)
import system
import setup
import nintendo
import ini

# Parse arguments
parser = argparse.ArgumentParser(description="Nintendo DS rom tool.")
parser.add_argument("path", help="Input path")
parser.add_argument("-d", "--decrypt", action="store_true", help="Decrypt NDS files")
parser.add_argument("-e", "--encrypt", action="store_true", help="Verify NDS files")
parser.add_argument("-g", "--generate_hash", action="store_true", help="Output size and hashes to a companion file")
args, unknown = parser.parse_known_args()
if not args.path:
    parser.print_help()
    sys.exit(-1)

# Check input path
input_path = os.path.realpath(args.path)
if not os.path.exists(input_path):
    system.LogError("Path '%s' does not exist" % args.path)
    sys.exit(-1)

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Get flags
    verbose = ini.GetIniBoolValue("UserData.Flags", "verbose")
    exit_on_failure = ini.GetIniBoolValue("UserData.Flags", "exit_on_failure")

    # Find rom files
    for file in system.BuildFileListByExtensions(input_path, extensions = [".nds"]):
        current_file = file
        current_file_dir = system.GetFilenameDirectory(current_file)
        current_file_basename = system.GetFilenameBasename(current_file)

        # Decrypt NDS file
        if args.decrypt:
            nintendo.DecryptNDSRom(
                nds_rom_file = current_file,
                generate_hash = args.generate_hash,
                verbose = verbose,
                exit_on_failure = exit_on_failure)

        # Encrypt NDS file
        elif args.encrypt:
            nintendo.EncryptNDSRom(
                nds_rom_file = current_file,
                generate_hash = args.generate_hash,
                verbose = verbose,
                exit_on_failure = exit_on_failure)

# Start
main()
