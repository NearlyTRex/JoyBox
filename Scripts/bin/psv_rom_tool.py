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
parser = argparse.ArgumentParser(description="Sony PlayStation Vita rom tool.")
parser.add_argument("path", help="Input path")
parser.add_argument("-s", "--strip", action="store_true", help="Strip PSV files")
parser.add_argument("-u", "--unstrip", action="store_true", help="Unstrip PSV files")
parser.add_argument("-t", "--trim", action="store_true", help="Trim PSV files")
parser.add_argument("-n", "--untrim", action="store_true", help="Untrim PSV files")
parser.add_argument("-v", "--verify", action="store_true", help="Verify PSV files")
parser.add_argument("-d", "--delete_originals", action="store_true", help="Delete original files")
args, unknown = parser.parse_known_args()
if not args.path:
    parser.print_help()
    sys.exit(-1)

# Check input path
input_path = os.path.realpath(args.path)
if not os.path.exists(input_path):
    print("Path '%s' does not exist" % args.path)
    sys.exit(-1)

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Get flags
    verbose = ini.GetIniBoolValue("UserData.Flags", "verbose")
    exit_on_failure = ini.GetIniBoolValue("UserData.Flags", "exit_on_failure")

    # Find psv files
    for file in system.BuildFileListByExtensions(input_path, extensions = [".psv"]):
        current_file = file
        current_file_dir = system.GetFilenameDirectory(current_file)
        current_file_basename = system.GetFilenameBasename(current_file)

        # Strip psv
        if args.strip:
            playstation.StripPSV(
                src_psv_file = current_file,
                dest_psv_file = os.path.join(current_file_dir, current_file_basename + "_stripped.psv"),
                delete_original = args.delete_originals,
                verbose = verbose,
                exit_on_failure = exit_on_failure)

        # Unstrip psv
        elif args.unstrip:
            playstation.UnstripPSV(
                src_psv_file = current_file,
                src_psve_file = os.path.join(current_file_dir, current_file_basename + ".psve"),
                dest_psv_file = os.path.join(current_file_dir, current_file_basename + "_unstripped.psv"),
                delete_original = args.delete_originals,
                verbose = verbose,
                exit_on_failure = exit_on_failure)

        # Trim psv
        elif args.trim:
            playstation.TrimPSV(
                src_psv_file = current_file,
                dest_psv_file = os.path.join(current_file_dir, current_file_basename + "_trimmed.psv"),
                delete_original = args.delete_originals,
                verbose = verbose,
                exit_on_failure = exit_on_failure)

        # Untrim psv
        elif args.untrim:
            playstation.UntrimPSV(
                src_psv_file = current_file,
                dest_psv_file = os.path.join(current_file_dir, current_file_basename + "_untrimmed.psv"),
                delete_original = args.delete_originals,
                verbose = verbose,
                exit_on_failure = exit_on_failure)

        # Verify psv
        elif args.verify:
            playstation.VerifyPSV(
                psv_file = current_file,
                verbose = verbose,
                exit_on_failure = exit_on_failure)

# Start
main()
