#!/usr/bin/env python3

# Imports
import os, os.path
import sys
import argparse

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.append(lib_folder)
import system
import playstation
import setup

# Parse arguments
parser = argparse.ArgumentParser(description="Sony PlayStation Network rom tool.")
parser.add_argument("path", help="Input path")
parser.add_argument("-r", "--rename", action="store_true", help="Rename PSN files using content ids")
parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose mode")
parser.add_argument("-x", "--exit_on_failure", action="store_true", help="Enable exit on failure mode")
args, unknown = parser.parse_known_args()
if not args.path:
    parser.print_help()
    system.QuitProgram()

# Check input path
input_path = os.path.realpath(args.path)
if not os.path.exists(input_path):
    system.LogErrorAndQuit("Path '%s' does not exist" % args.path)

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Rename psn files
    if args.rename:
        for rap_file in system.BuildFileListByExtensions(input_path, extensions = [".rap"]):
            playstation.RenamePSNRapFile(
                rap_file = rap_file,
                verbose = args.verbose,
                exit_on_failure = args.exit_on_failure)
        for pkg_file in system.BuildFileListByExtensions(input_path, extensions = [".pkg"]):
            playstation.RenamePSNPackageFile(
                pkg_file = pkg_file,
                verbose = args.verbose,
                exit_on_failure = args.exit_on_failure)
        for bin_file in system.BuildFileListByExtensions(input_path, extensions = [".bin"]):
            if bin_file.endswith(".work.bin"):
                playstation.RenamePSNWorkBinFile(
                    workbin_file = bin_file,
                    verbose = args.verbose,
                    exit_on_failure = args.exit_on_failure)
        for rif_file in system.BuildFileListByExtensions(input_path, extensions = [".rif"]):
            if rif_file.endswith(".fake.rif"):
                playstation.RenamePSNFakeRifFile(
                    fakerif_file = rif_file,
                    verbose = args.verbose,
                    exit_on_failure = args.exit_on_failure)

# Start
main()
