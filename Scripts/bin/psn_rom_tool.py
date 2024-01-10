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
import ini

# Parse arguments
parser = argparse.ArgumentParser(description="Sony PlayStation Network rom tool.")
parser.add_argument("path", help="Input path")
parser.add_argument("-r", "--rename", action="store_true", help="Rename PSN files using content ids")
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

    # Rename psn files
    if args.rename:
        for rap_file in system.BuildFileListByExtensions(input_path, extensions = [".rap"]):
            playstation.RenamePSNRapFile(
                rap_file = rap_file,
                verbose = verbose,
                exit_on_failure = exit_on_failure)
        for pkg_file in system.BuildFileListByExtensions(input_path, extensions = [".pkg"]):
            playstation.RenamePSNPackageFile(
                pkg_file = pkg_file,
                verbose = verbose,
                exit_on_failure = exit_on_failure)
        for bin_file in system.BuildFileListByExtensions(input_path, extensions = [".bin"]):
            if bin_file.endswith(".work.bin"):
                playstation.RenamePSNWorkBinFile(
                    workbin_file = bin_file,
                    verbose = verbose,
                    exit_on_failure = exit_on_failure)
        for rif_file in system.BuildFileListByExtensions(input_path, extensions = [".rif"]):
            if rif_file.endswith(".fake.rif"):
                playstation.RenamePSNFakeRifFile(
                    fakerif_file = rif_file,
                    verbose = verbose,
                    exit_on_failure = exit_on_failure)

# Start
main()
